package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.dto.siem.PreventionDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.service.siem.SiemElasticGateway;
import com.flarefitness.backend.service.siem.SiemPreventionEventIngestionService;
import com.flarefitness.backend.service.siem.SiemPreventionService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@SpringBootTest
class SiemPreventionIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private SiemPreventionEventIngestionService ingestion;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private SiemPreventionService prevention;
    @Autowired private UserRepository users;

    @Test
    @org.springframework.transaction.annotation.Transactional
    void stricterScopeRejectsNewBlocksButExistingHistoryCanStillBeRevokedById() {
        User actor = new User();
        actor.setId("scope-actor-" + UUID.randomUUID());
        actor.setUsername("scope-actor-" + UUID.randomUUID());
        actor.setPassword("unused-synthetic-fixture"); actor.setRole("SOC L2");
        actor.setHoTen("Owned IP scope actor"); actor.setStatus("ACTIVE");
        actor.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(actor);
        var principal = new CurrentUserPrincipal(actor);
        var authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        assertThatThrownBy(() -> prevention.createIpBlock(new PreventionDtos.CreateIpBlock(
                "192.0.0.1", "Owned non-global manual regression", 15L, null), authentication))
                .isInstanceOf(BadRequestException.class);

        String id = "old-scope-block-" + UUID.randomUUID();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                INSERT INTO siem_ip_blocks (id,ip_address,reason,source_type,started_at,expires_at,version)
                VALUES (?,'192.0.0.1','Owned historical scope fixture','MANUAL',?,?,0)
                """, id, now, now.plusMinutes(15));
        var released = prevention.revokeIpBlock(id, 0, authentication);
        assertThat(released.revokedAt()).isNotNull();
        assertThat(released.version()).isEqualTo(1);
        assertThat(released.ipAddress()).isEqualTo("192.0.0.1");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_ip_blocks WHERE id=?", Long.class, id)).isEqualTo(1);
    }

    @Test
    void repeatedApprovedSignatureCreatesOneTimedBlockAndOneSocIncident() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        List<SiemElasticGateway.PreventionEvent> events = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            String id = UUID.randomUUID().toString().replace("-", "");
            events.add(new SiemElasticGateway.PreventionEvent(id, id, "8.8.8.8",
                    "SIGNATURE_MATCH", "sig-test-12345678", 1, "DENY", 1,
                    now.minusSeconds(3 - i)));
        }
        assertThat(ingestion.ingest(events)).isEqualTo(3);
        assertThat(ingestion.ingest(events)).isZero();
        assertThat(incidents.countByTargetUserIdAndOrigin("missing", IncidentOrigin.PREVENTION)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_incidents
                WHERE origin='PREVENTION' AND source_ip='8.8.8.8'
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT incident_nature FROM siem_incidents
                WHERE origin='PREVENTION' AND source_ip='8.8.8.8'
                """, String.class)).isEqualTo(IncidentNature.SECURITY_DETECTION.name());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address='8.8.8.8'
                  AND source_type='SIGNATURE' AND expires_at>UTC_TIMESTAMP()
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address='8.8.8.8'
                """, Long.class)).isEqualTo(1);
    }

    @Test
    void separateCompletedScanWindowsAreRequiredForAutomaticBan() {
        LocalDateTime minute = LocalDateTime.now(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.MINUTES).minusMinutes(1);
        var candidate = new SiemElasticGateway.IpScanCandidate("8.8.4.4", 22, 12);
        ingestion.ingestScanCandidate(candidate, minute.minusMinutes(1).plusSeconds(59));
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address='8.8.4.4'
                """, Long.class)).isZero();
        ingestion.ingestScanCandidate(candidate, minute.plusSeconds(59));
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address='8.8.4.4'
                  AND source_type='SCAN'
                """, Long.class)).isEqualTo(1);
    }

    @Test
    void repeatedAggregatedRateLimitSignalsCreateTimedFloodBlock() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        String firstId = UUID.randomUUID().toString().replace("-", "");
        String secondId = UUID.randomUUID().toString().replace("-", "");
        var previous = new SiemElasticGateway.PreventionEvent(firstId, firstId, "9.9.9.9",
                "RATE_LIMIT", null, 1, "THROTTLE", 105, now.minusSeconds(90));
        var current = new SiemElasticGateway.PreventionEvent(secondId, secondId, "9.9.9.9",
                "RATE_LIMIT", null, 1, "THROTTLE", 110, now.minusSeconds(10));

        assertThat(ingestion.ingest(List.of(previous))).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address='9.9.9.9'
                  AND source_type='HTTP_FLOOD'
                """, Long.class)).isZero();

        assertThat(ingestion.ingest(List.of(current))).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_prevention_events WHERE ip_address='9.9.9.9'
                  AND event_type='RATE_LIMIT' AND signal_count>=100
                """, Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address='9.9.9.9'
                  AND source_type='HTTP_FLOOD' AND expires_at>UTC_TIMESTAMP()
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_incidents WHERE source_ip='9.9.9.9'
                  AND rule_id='FLARE_PREVENTION_HTTP_FLOOD'
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT incident_nature FROM siem_incidents WHERE source_ip='9.9.9.9'
                  AND rule_id='FLARE_PREVENTION_HTTP_FLOOD'
                """, String.class)).isEqualTo(IncidentNature.SECURITY_DETECTION.name());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address='9.9.9.9'
                """, Long.class)).isEqualTo(1);
    }
}
