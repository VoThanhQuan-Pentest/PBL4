package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.DriverManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

class SiemPreventionDateTimeIntegrationTest {
    @Test
    @ResourceLock("default-timezone")
    void readsUtcClockValuesWithoutApplyingTheMysqlConnectionTimezone() throws Exception {
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try (var db = new MySQLContainer<>(DockerImageName.parse(
                "mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
                .asCompatibleSubstituteFor("mysql"))) {
            db.start();
            String url = db.getJdbcUrl() + (db.getJdbcUrl().contains("?") ? "&" : "?")
                    + "connectionTimeZone=Asia/Ho_Chi_Minh";
            try (var connection = DriverManager.getConnection(url, db.getUsername(), db.getPassword());
                    var statement = connection.createStatement()) {
                LocalDateTime expires = LocalDateTime.now(ZoneOffset.UTC).plusHours(6).withNano(0);
                statement.execute("CREATE TABLE security_clock_fixture (expires_at DATETIME(6), revoked_at DATETIME(6))");
                try (var insert = connection.prepareStatement("INSERT INTO security_clock_fixture VALUES (?,NULL)")) {
                    insert.setObject(1, expires);
                    insert.executeUpdate();
                }
                try (var row = statement.executeQuery("SELECT * FROM security_clock_fixture")) {
                    assertThat(row.next()).isTrue();
                    assertThat(row.getTimestamp("expires_at").toLocalDateTime()).isEqualTo(expires.minusHours(7));
                    assertThat(SiemPreventionService.timestamp(row, "expires_at")).isEqualTo(expires);
                    assertThat(SiemPreventionService.timestamp(row, "revoked_at")).isNull();
                    assertThat(SiemPreventionService.timestamp(row, "expires_at"))
                            .isAfter(LocalDateTime.now(ZoneOffset.UTC));
                }
            }
        } finally {
            TimeZone.setDefault(original);
        }
    }
}
