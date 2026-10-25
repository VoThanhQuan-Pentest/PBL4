package com.flarefitness.backend.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;
import java.sql.DriverManager;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

class AwsLabBootstrapTest {
    @Test
    void requiresAwsAndCreatesOnlyOneAdminWithTheApplicationEncoder() throws Exception {
        assertThatThrownBy(() -> AwsLabBootstrap.requireEnvironment("local"))
                .isInstanceOf(IllegalStateException.class);
        AwsLabBootstrap.requireEnvironment("aws-lab");
        try (var db = new MySQLContainer<>(DockerImageName.parse(
                "mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
                .asCompatibleSubstituteFor("mysql"))) {
            db.start();
            Flyway.configure().dataSource(db.getJdbcUrl(), db.getUsername(), db.getPassword())
                    .locations("classpath:db/migration").load().migrate();
            try (var connection = DriverManager.getConnection(db.getJdbcUrl(), db.getUsername(), db.getPassword())) {
                var credential = AwsLabBootstrap.create(connection);
                try (var statement = connection.prepareStatement("SELECT password,role FROM tbl_nguoi_dung WHERE id=?")) {
                    statement.setString(1, credential.get("id"));
                    try (var row = statement.executeQuery()) {
                        assertThat(row.next()).isTrue();
                        assertThat(row.getString(2)).isEqualTo("Admin");
                        assertThat(new BcryptSha256PasswordEncoder(12).matches(credential.get("password"), row.getString(1))).isTrue();
                    }
                }
                assertThatThrownBy(() -> AwsLabBootstrap.create(connection)).isInstanceOf(IllegalStateException.class);
            }
        }
    }
}
