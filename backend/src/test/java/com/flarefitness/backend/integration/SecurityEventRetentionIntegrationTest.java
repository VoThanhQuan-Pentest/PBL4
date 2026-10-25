package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SecurityEventRetentionWorker;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
class SecurityEventRetentionIntegrationTest extends ContainerizedIntegrationTest {
    @TempDir Path directory;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private JdbcTemplate jdbc;

    @Test
    @Transactional
    void deletesOnlyExportedAggregatedOldEventsAndScoredOldWindows() {
        LocalDateTime old = LocalDateTime.now(ZoneOffset.UTC).minusDays(40);
        String prefix = "retention-" + UUID.randomUUID().toString().substring(0, 8);
        SiemSecurityEvent processed = event(prefix + "-processed", old);
        processed.setExportedAt(old);
        processed.setAggregatedAt(old);
        SiemSecurityEvent notExported = event(prefix + "-not-exported", old);
        notExported.setAggregatedAt(old);
        SiemSecurityEvent notAggregated = event(prefix + "-not-aggregated", old);
        notAggregated.setExportedAt(old);
        events.saveAllAndFlush(List.of(processed, notExported, notAggregated));

        SiemAccountBehaviorWindow scored = window(prefix + "-scored", old, true);
        SiemAccountBehaviorWindow pending = window(prefix + "-pending", old.plusMinutes(15), false);
        windows.saveAllAndFlush(List.of(scored, pending));
        new SecurityEventRetentionWorker(events, windows, true, 30,
                directory.resolve("security-events.ndjson").toString()).purgeExpired();

        assertThat(count("siem_security_events", processed.getId())).isZero();
        assertThat(count("siem_security_events", notExported.getId())).isEqualTo(1);
        assertThat(count("siem_security_events", notAggregated.getId())).isEqualTo(1);
        assertThat(count("siem_account_behavior_windows", scored.getId())).isZero();
        assertThat(count("siem_account_behavior_windows", pending.getId())).isEqualTo(1);
    }

    private int count(String table, String id) {
        // The table name is one of two constants in this test; the ID remains parameterized.
        return jdbc.queryForObject("SELECT COUNT(*) FROM " + table + " WHERE id = ?", Integer.class, id);
    }

    private SiemSecurityEvent event(String id, LocalDateTime at) {
        SiemSecurityEvent event = new SiemSecurityEvent();
        event.setId(id);
        event.setEventTimestamp(at);
        event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST");
        event.setOutcome("SUCCESS");
        event.setCreatedAt(at);
        return event;
    }

    private SiemAccountBehaviorWindow window(String id, LocalDateTime at, boolean scored) {
        SiemAccountBehaviorWindow window = new SiemAccountBehaviorWindow();
        window.setId(id);
        window.setAccountId(id);
        window.setWindowStart(at);
        window.setWindowEnd(at.plusMinutes(15));
        window.setCreatedAt(at);
        window.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                List.of(1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0)),
                1, false, "203.0.113.10", "CHROMIUM", "REAL", at);
        if (scored) window.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment(
                null, null, 0, "normal"), at);
        return window;
    }
}
