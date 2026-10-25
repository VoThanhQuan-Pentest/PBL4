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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    private void insertFailedLogin(LocalDateTime when, String sourceIp) {
        jdbc.update("""
                INSERT INTO siem_security_events
                    (id,event_timestamp,source_ip,event_type,action,outcome,ngay_tao)
                VALUES (?,?,?,'AUTH','LOGIN','FAILURE',?)
                """, "ip-risk-test-" + UUID.randomUUID(), when, sourceIp, when);
    }

    private String uniquePublicTestIp() {
        int lastOctet = 1 + Math.floorMod(UUID.randomUUID().hashCode(), 254);
        return "8.8.4." + lastOctet;
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
