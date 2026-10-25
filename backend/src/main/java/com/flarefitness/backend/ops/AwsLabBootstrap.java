package com.flarefitness.backend.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/** SSH-only operator entry point, launched with Boot PropertiesLauncher, never an HTTP API. */
public final class AwsLabBootstrap {
    private AwsLabBootstrap() { }

    public static void main(String[] args) {
        if (args.length == 1 && "--help".equals(args[0])) {
            System.out.println("AWS-only bootstrap: capture stdout in a private 0600 file; requires an empty Admin set.");
            return;
        }
        try {
            requireEnvironment(System.getenv("FLARE_ENVIRONMENT"));
            if (args.length == 1 && "hash-password".equals(args[0])) {
                byte[] bytes = System.in.readNBytes(129);
                if (bytes.length < 12 || bytes.length > 128) throw new IllegalArgumentException("Password size");
                System.out.println(new BcryptSha256PasswordEncoder(12).encode(
                        new String(bytes, java.nio.charset.StandardCharsets.UTF_8)));
                return;
            }
            if (args.length != 0) throw new IllegalArgumentException("Unknown command");
            try (Connection connection = DriverManager.getConnection(
                    System.getenv("SPRING_DATASOURCE_URL"),
                    System.getenv("SPRING_DATASOURCE_USERNAME"),
                    System.getenv("SPRING_DATASOURCE_PASSWORD"))) {
                var result = create(connection);
                System.out.println(new ObjectMapper().writeValueAsString(result));
            }
        } catch (Exception failure) {
            // Never print JDBC URLs, passwords or SQL exception messages.
            System.err.println("Bootstrap refused/failed: " + failure.getClass().getSimpleName());
            System.exit(2);
        }
    }

    static void requireEnvironment(String environment) {
        if (!"aws-lab".equals(environment)) throw new IllegalStateException("AWS lab required");
    }

    static Map<String, String> create(Connection connection) throws Exception {
        try (var lock = connection.prepareStatement("SELECT GET_LOCK('flare-aws-bootstrap',5)")) {
            try (var row = lock.executeQuery()) {
                if (!row.next() || row.getInt(1) != 1) throw new IllegalStateException("Bootstrap lock unavailable");
            }
        }
        try {
            try (var statement = connection.prepareStatement("SELECT COUNT(*) FROM tbl_nguoi_dung WHERE LOWER(role) IN ('admin','quan tri vien') AND is_deleted=0")) {
                try (var row = statement.executeQuery()) {
                    row.next();
                    if (row.getInt(1) != 0) throw new IllegalStateException("Admin already exists");
                }
            }
            String suffix = UUID.randomUUID().toString().replace("-", "");
            byte[] entropy = new byte[24];
            new SecureRandom().nextBytes(entropy);
            String password = "Aws#" + HexFormat.of().formatHex(entropy);
            String id = "aws-bootstrap-" + suffix;
            String username = "aws_bootstrap_" + suffix.substring(0, 10);
            try (var insert = connection.prepareStatement("""
                    INSERT INTO tbl_nguoi_dung
                      (id,username,password,role,ho_ten,trang_thai,is_deleted,auth_version)
                    VALUES (?,?,?,'Admin','Temporary AWS bootstrap','Hoat dong',0,0)
                    """)) {
                insert.setString(1, id);
                insert.setString(2, username);
                insert.setString(3, new BcryptSha256PasswordEncoder(12).encode(password));
                insert.executeUpdate();
            }
            return Map.of("id", id, "username", username, "password", password);
        } finally {
            try (var release = connection.prepareStatement("SELECT RELEASE_LOCK('flare-aws-bootstrap')")) {
                release.execute();
            }
        }
    }
}
