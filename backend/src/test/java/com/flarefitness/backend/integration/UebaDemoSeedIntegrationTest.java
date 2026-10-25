package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;
import com.flarefitness.backend.service.siem.AccountBehaviorAggregationWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorScoringWorker;
import com.flarefitness.backend.service.AuthService;
import com.flarefitness.backend.dto.auth.LoginRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/** Exercises the exact local SQL fixture against isolated Testcontainers MySQL. */
@SpringBootTest
class UebaDemoSeedIntegrationTest extends ContainerizedIntegrationTest {
    private static final String DATASET = "ueba-contract";
    @Autowired private DataSource dataSource;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private AccountBehaviorAggregationWorker aggregation;
    @Autowired private AccountBehaviorScoringWorker scoring;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private AuthService authService;

    @Test
    void labelledHistoryCanTrainAndAbnormalTrafficProducesOneRuleFallbackCase() throws Exception {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC).truncatedTo(java.time.temporal.ChronoUnit.HOURS);
        String instant = DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(now.atOffset(ZoneOffset.UTC));
        String passwordHash = new BcryptSha256PasswordEncoder(12).encode("DemoOnly#2026");
        applyFixture("normal", instant, passwordHash);
        applyFixture("normal", instant, passwordHash);
        assertThat(count("SELECT COUNT(*) FROM siem_security_events WHERE demo_label = 'NORMAL'"))
                .isEqualTo(2532);
        assertThat(authService.login(new LoginRequest("ueba_demo_" + DATASET + "_1", "DemoOnly#2026"),
                "127.0.0.1").accessToken()).isNotBlank();

        drainAggregation(now, "NORMAL");
        var normalWindows = windows.findAll().stream()
                .filter(window -> "NORMAL".equals(window.getDemoLabel())).toList();
        assertThat(normalWindows).hasSize(960);
        long eligible = normalWindows.stream().filter(this::eligibleDemoNormal).count();
        assertThat(eligible).as("normal windows available for 500+100 training/calibration")
                .isGreaterThanOrEqualTo(600);

        applyFixture("abnormal", instant, null);
        applyFixture("abnormal", instant, null);
        assertThat(count("SELECT COUNT(*) FROM siem_security_events WHERE demo_label = 'ABNORMAL'"))
                .isEqualTo(136);
        drainAggregation(now, "ABNORMAL");
        String target = "ueba-demo-" + DATASET + "-1";
        SiemAccountBehaviorWindow anomaly = windows.findAll().stream()
                .filter(window -> target.equals(window.getAccountId())
                        && "ABNORMAL".equals(window.getDemoLabel())).findFirst().orElseThrow();
        for (int attempt = 0; attempt < 12 && anomaly.getScoreStatus() == BehaviorScoreStatus.PENDING; attempt++) {
            scoring.scorePendingAt(now);
            anomaly = windows.findById(anomaly.getId()).orElseThrow();
        }
        assertThat(anomaly.getScoreStatus()).isEqualTo(BehaviorScoreStatus.SCORED_RULE_ONLY);
        assertThat(anomaly.getModelVersion()).isNull();
        assertThat(anomaly.getRiskScore()).isGreaterThanOrEqualTo(45);
        assertThat(incidents.countByTargetUserIdAndOrigin(target, IncidentOrigin.UEBA)).isEqualTo(1);
        var incident = incidents.findAll().stream()
                .filter(value -> target.equals(value.getTargetUserId()) && value.getOrigin() == IncidentOrigin.UEBA)
                .findFirst().orElseThrow();
        assertThat(incident.getDetectorModelVersion()).isNull();
        assertThat(incident.getNature()).isEqualTo(IncidentNature.ACCOUNT_BEHAVIOR_ANOMALY);
    }

    private boolean eligibleDemoNormal(SiemAccountBehaviorWindow window) {
        var values = window.featureVector();
        return window.isBaselineEstablished() && values.get(1) <= 1 && values.get(2) == 0
                && values.get(3) <= 1 && values.get(5) == 0
                && values.get(8) == 0 && values.get(9) == 0 && values.get(10) == 0
                && values.get(0) < 60;
    }

    private void drainAggregation(LocalDateTime now, String label) {
        for (int attempt = 0; attempt < 25 && pending(label) > 0; attempt++) {
            aggregation.aggregatePendingAt(now);
        }
        assertThat(pending(label)).isZero();
    }

    private long pending(String label) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM siem_security_events "
                + "WHERE demo_label = ? AND aggregated_at IS NULL", Long.class, label);
    }

    private long count(String sql) {
        return jdbc.queryForObject(sql, Long.class);
    }

    private void applyFixture(String mode, String instant, String passwordHash) throws Exception {
        Path script = Path.of("..", "observability", "scripts", "seed-ueba-demo.py")
                .toAbsolutePath().normalize();
        var command = new java.util.ArrayList<String>();
        command.addAll(java.util.List.of("python3", script.toString(), mode,
                "--dataset-id", DATASET, "--now", instant));
        if (passwordHash != null) command.addAll(java.util.List.of("--password-hash", passwordHash));
        Process process = new ProcessBuilder(command).start();
        String sql = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(process.waitFor(20, TimeUnit.SECONDS)).isTrue();
        assertThat(process.exitValue()).isZero();
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            connection.setAutoCommit(false);
            for (String line : sql.lines().toList()) {
                if (line.startsWith("INSERT IGNORE")) statement.addBatch(line);
            }
            statement.executeBatch();
            connection.commit();
        }
    }
}
