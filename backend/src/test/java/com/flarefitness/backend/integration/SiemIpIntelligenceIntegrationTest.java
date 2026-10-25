package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.siem.SiemIpIntelligenceWorker;
import com.flarefitness.backend.service.siem.SiemIpRiskTriggerWorker;
import com.flarefitness.backend.service.siem.SiemPreventionService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(properties = {
        "siem.prevention.enabled=true",
        "siem.prevention.demo-enabled=true",
        "siem.prevention.ipinfo-token-file=/tmp/flare-test-no-ipinfo-key",
        "siem.prevention.abuseipdb-key-file=/tmp/flare-test-no-abuseipdb-key"
})
class SiemIpIntelligenceIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private JdbcTemplate jdbc;
    @Autowired private SiemIpIntelligenceWorker worker;
    @Autowired private SiemIpRiskTriggerWorker riskTriggers;
    @Autowired private SiemPreventionService service;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private PlatformTransactionManager transactions;

    @Test
    void missingProviderKeysAreReportedAndDemoDataIsExplicitlyMarked() {
        String requestId = "ip-lookup-test-" + UUID.randomUUID();
        String providerIp = uniquePublicTestIp();
        jdbc.update("""
                INSERT INTO siem_ip_lookup_requests
                    (id,ip_address,reason,status,requested_at)
                VALUES (?,?,'TEST_FIXTURE','PENDING',?)
                """, requestId, providerIp, LocalDateTime.now(ZoneOffset.UTC).minusYears(20));
        for (int index = 0; index < 5; index++) {
            worker.processOne();
            String status = jdbc.queryForObject(
                    "SELECT status FROM siem_ip_lookup_requests WHERE id=?", String.class, requestId);
            if ("DONE".equals(status)) break;
        }
        assertThat(jdbc.queryForObject(
                "SELECT status FROM siem_ip_lookup_requests WHERE id=?", String.class, requestId))
                .isEqualTo("DONE");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_intelligence
                WHERE ip_address=? AND status='NOT_CONFIGURED'
                  AND data_provenance='UNAVAILABLE'
                """, Long.class, providerIp)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_ip_provider_attempts WHERE ip_address=?",
                Long.class, providerIp)).isZero();

        List<com.flarefitness.backend.dto.siem.PreventionDtos.IpIntelligence> fixture =
                service.seedDemoIntelligence(admin());
        assertThat(fixture).hasSize(2);
        assertThat(fixture).allSatisfy(item -> {
            assertThat(item.ipAddress()).isEqualTo("203.0.113.55");
            assertThat(item.dataProvenance()).isEqualTo("DEMO_ONLY");
            assertThat(item.status()).isEqualTo("DEMO");
        });
        assertThat(fixture.stream().filter(item -> "ABUSEIPDB".equals(item.provider()))
                .findFirst().orElseThrow().abuseScore()).isEqualTo(80);
    }

    @Test
    void fiveFailedLoginsQueueOneLookupWithoutBlockingSharedIp() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        String riskIp = uniquePublicTestIp();
        for (int index = 0; index < 4; index++) insertFailedLogin(now.plusNanos(index), riskIp);
        riskTriggers.scheduleSuspiciousIps();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address=?
                """, Long.class, riskIp)).isZero();

        insertFailedLogin(now.plusNanos(4), riskIp);
        riskTriggers.scheduleSuspiciousIps();
        riskTriggers.scheduleSuspiciousIps();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address=?
                """, Long.class, riskIp)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address=?
                """, Long.class, riskIp)).isZero();
    }

    @Test
    void concurrentLookupAdmissionUsesTheCommittedWinnerEvenWithAnOlderTransactionSnapshot() throws Exception {
        String ip = uniquePublicTestIp();
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var tasks = java.util.stream.IntStream.range(0, 2).mapToObj(ignored -> executor.submit(() -> {
                new TransactionTemplate(transactions).executeWithoutResult(status -> {
                    // Both callers establish their snapshot before either can insert.
                    assertThat(jdbc.queryForObject(
                            "SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address=?", Long.class, ip)).isZero();
                    ready.countDown();
                    try {
                        if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Admission start timed out");
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(interrupted);
                    }
                    service.requestLookupForSignal(ip, "CONCURRENT_TEST_FIXTURE");
                });
            })).toList();
            try {
                assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            } finally {
                start.countDown();
            }
            for (var task : tasks) task.get(20, TimeUnit.SECONDS);
        }
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address=?", Long.class, ip)).isEqualTo(1);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address=?", Long.class, ip)).isZero();
    }

    private void insertFailedLogin(LocalDateTime when, String sourceIp) {
        jdbc.update("""
                INSERT INTO siem_security_events
                    (id,event_timestamp,source_ip,event_type,action,outcome,ngay_tao)
                VALUES (?,?,?,'AUTH','LOGIN','FAILURE',?)
                """, "ip-risk-test-" + UUID.randomUUID(), when, sourceIp, when);
    }

    private String uniquePublicTestIp() {
        // Avoid collisions with another test's retained history in a /24 pool.
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String address = "2606:4700:" + java.util.stream.IntStream.range(0, 6)
                .mapToObj(index -> suffix.substring(index * 4, index * 4 + 4))
                .collect(java.util.stream.Collectors.joining(":"));
        return SiemPreventionService.canonicalPublicIp(address);
    }

    private Authentication admin() {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        User user = new User();
        user.setId("prevention-admin-" + suffix);
        user.setUsername("prevention_admin_" + suffix);
        user.setPassword(passwords.encode("Integration#1"));
        user.setRole("Admin");
        user.setHoTen("Prevention integration administrator");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(user);
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
