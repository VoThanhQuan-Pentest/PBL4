package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.sql.DriverManager;
import java.time.LocalDateTime;
import java.util.TimeZone;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

class SiemUtcJpaIntegrationTest {
    @Test
    @ResourceLock("default-timezone")
    void nativeUtcEventsAndJpaRoundTripAgreeWithoutChangingLegacyBusinessDates() throws Exception {
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try (var db = new MySQLContainer<>(DockerImageName.parse(
                "mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
                .asCompatibleSubstituteFor("mysql"))) {
            db.start();
            String url = db.getJdbcUrl() + (db.getJdbcUrl().contains("?") ? "&" : "?")
                    + "connectionTimeZone=Asia/Ho_Chi_Minh";
            Configuration config = new Configuration().addAnnotatedClass(SiemSecurityEvent.class)
                    .addAnnotatedClass(SiemAccountBehaviorWindow.class)
                    .setProperty("hibernate.connection.driver_class", "com.mysql.cj.jdbc.Driver")
                    .setProperty("hibernate.connection.url", url)
                    .setProperty("hibernate.connection.username", db.getUsername())
                    .setProperty("hibernate.connection.password", db.getPassword())
                    .setProperty("hibernate.jdbc.time_zone", "Asia/Ho_Chi_Minh")
                    .setProperty("hibernate.hbm2ddl.auto", "create");
            LocalDateTime clock = LocalDateTime.of(2026, 9, 30, 12, 0);
            try (var factory = config.buildSessionFactory();
                    var connection = DriverManager.getConnection(url, db.getUsername(), db.getPassword())) {
                try (var insert = connection.prepareStatement("""
                        INSERT INTO siem_security_events
                         (id,event_timestamp,event_type,action,outcome,demo_label,ngay_tao)
                        VALUES ('native-utc',?,'HTTP_REQUEST','API_REQUEST','SUCCESS','ABNORMAL',?)
                        """)) {
                    insert.setObject(1, clock);
                    insert.setObject(2, clock);
                    insert.executeUpdate();
                }
                try (var session = factory.openSession()) {
                    assertThat(session.createQuery("select max(w.windowStart) from SiemAccountBehaviorWindow w",
                            LocalDateTime.class).getSingleResult()).isNull();
                    assertThat(session.find(SiemSecurityEvent.class, "native-utc").getEventTimestamp()).isEqualTo(clock);
                    var transaction = session.beginTransaction();
                    SiemSecurityEvent row = new SiemSecurityEvent();
                    row.setId("orm-utc"); row.setEventTimestamp(clock); row.setCreatedAt(clock);
                    row.setEventType("HTTP_REQUEST"); row.setAction("API_REQUEST"); row.setOutcome("SUCCESS");
                    session.persist(row);
                    transaction.commit();
                    session.clear();
                    assertThat(session.find(SiemSecurityEvent.class, "orm-utc").getEventTimestamp()).isEqualTo(clock);
                }
                try (var statement = connection.createStatement();
                        var result = statement.executeQuery("SELECT event_timestamp,ngay_tao FROM siem_security_events WHERE id='orm-utc'")) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getObject("event_timestamp", LocalDateTime.class)).isEqualTo(clock);
                    assertThat(result.getObject("ngay_tao", LocalDateTime.class)).isEqualTo(clock.plusHours(7));
                }
            }
        } finally {
            TimeZone.setDefault(original);
        }
    }
}
