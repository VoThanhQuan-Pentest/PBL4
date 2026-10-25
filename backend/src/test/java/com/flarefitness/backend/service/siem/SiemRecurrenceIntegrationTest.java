package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.integration.ContainerizedIntegrationTest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.mockito.Mockito.*;

@SpringBootTest(properties="siem.prevention.recurrence-mode=ENFORCE")
class SiemRecurrenceIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired SiemPreventionService prevention;
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @MockitoBean SiemPreventionGateway gateway;
    String signature;
    long policy;
    final LocalDateTime base=LocalDateTime.now(ZoneOffset.UTC).minusDays(4).withNano(0);
    @BeforeEach void setup() throws Exception {
        when(gateway.health()).thenReturn(new SiemPreventionGateway.GatewayHealth(true,1,"UP",true));
        signature="sig-"+UUID.randomUUID();
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("PATH_EXACT|null|null|/bad|HIGH".getBytes(StandardCharsets.UTF_8)));
        jdbc.update("INSERT INTO siem_attack_signatures (id,version,kind,match_value,severity,status,action,created_by_user_id,approved_by_user_id,tested_definition_hash,created_at,updated_at,approved_at) VALUES (?,2,'PATH_EXACT','/bad','HIGH','ACTIVE','BLOCK','admin','admin',?,?,?,?)",signature,hash,base.minusDays(1),base.minusDays(1),base.minusDays(1));
        String json=mapper.writeValueAsString(Map.of("schema_version",2,"signatures",List.of(Map.of("id",signature,"kind","PATH_EXACT","match_value","/bad","action","BLOCK","definition_hash",hash,"definition_version",1)),"blocks",List.of()));
        jdbc.update("INSERT INTO siem_prevention_policies (checksum,policy_json,published_at,acknowledged_at) VALUES (?,?,?,?)","0".repeat(64),json,base.minusDays(1),base.minusDays(1));
        policy=jdbc.queryForObject("SELECT MAX(version) FROM siem_prevention_policies",Long.class);
    }
    SiemElasticGateway.PreventionEvent event(String ip,LocalDateTime time,String request) {
        return new SiemElasticGateway.PreventionEvent(UUID.randomUUID().toString().replace("-",""),request,ip,"SIGNATURE_MATCH",signature,policy,"DENY",1,time,"LIVE_GATEWAY");
    }
    void episode(String ip,LocalDateTime now) {
        for(int n=2;n>=0;n--)prevention.qualifySignatureEpisode(event(ip,now.minusSeconds(n),UUID.randomUUID().toString()),"practice-case",now);
    }
    @Test void fourIndependentEpisodesEscalateWithoutInventingExpiryAndReplayCannotAddStrikes() {
        String ip="8.26.56.26";
        episode(ip,base);
        episode(ip,base.plusHours(25));
        episode(ip,base.plusHours(50));
        episode(ip,base.plusHours(75));
        var rows=jdbc.queryForList("SELECT duration_type,started_at,expires_at FROM siem_ip_blocks WHERE ip_address=? ORDER BY started_at",ip);
        assertThat(rows).hasSize(4);
        assertThat(Duration.between((LocalDateTime)rows.get(0).get("started_at"),(LocalDateTime)rows.get(0).get("expires_at")).toMinutes()).isEqualTo(15);
        assertThat(Duration.between((LocalDateTime)rows.get(1).get("started_at"),(LocalDateTime)rows.get(1).get("expires_at")).toMinutes()).isEqualTo(60);
        assertThat(Duration.between((LocalDateTime)rows.get(2).get("started_at"),(LocalDateTime)rows.get(2).get("expires_at")).toHours()).isEqualTo(24);
        assertThat(rows.get(3).get("expires_at")).isNull();assertThat(rows.get(3).get("duration_type")).isEqualTo("UNTIL_REVOKED");
        episode(ip,base.plusHours(76));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=?",Long.class,ip)).isEqualTo(4);
    }
    @Test void duplicateRequestsAndUnverifiedPrivateFutureOrBacklogEvidenceDoNotEscalate() {
        String ip="64.6.64.6",request=UUID.randomUUID().toString();
        for(int n=0;n<5;n++)prevention.qualifySignatureEpisode(event(ip,base,request),"practice-case",base);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address=?",Long.class,ip)).isZero();
        var unverified=new SiemElasticGateway.PreventionEvent("a".repeat(32),"b".repeat(32),ip,"SIGNATURE_MATCH",signature,policy,"DENY",1,base);
        assertThat(prevention.qualifySignatureEpisode(unverified,"practice-case",base)).isFalse();
        assertThat(prevention.qualifySignatureEpisode(event("203.0.113.5",base,"fixture"),"practice-case",base)).isFalse();
        assertThat(prevention.qualifySignatureEpisode(event(ip,base.minusMinutes(6),"stale"),"practice-case",base)).isFalse();
        assertThat(prevention.qualifySignatureEpisode(event(ip,base.plusMinutes(3),"future"),"practice-case",base)).isFalse();
    }
    @Test void concurrentWorkersCreateOneStrikeForTheSameThreeRequests() throws Exception {
        String ip="64.6.65.6";
        var events=List.of(event(ip,base.minusSeconds(2),"request-a"),event(ip,base.minusSeconds(1),"request-b"),event(ip,base,"request-c"));
        try(var pool=java.util.concurrent.Executors.newFixedThreadPool(2)){
            var first=pool.submit(()->events.forEach(e->prevention.qualifySignatureEpisode(e,"practice-case",base)));
            var second=pool.submit(()->events.forEach(e->prevention.qualifySignatureEpisode(e,"practice-case",base)));
            first.get(15,java.util.concurrent.TimeUnit.SECONDS);second.get(15,java.util.concurrent.TimeUnit.SECONDS);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=?",Long.class,ip)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_signature_requests WHERE ip_address=?",Long.class,ip)).isEqualTo(3);
    }

    @Test void reasonedFalsePositiveRevocationInvalidatesStrikeWithoutDeletingHistory() {
        String ip="151.101.1.69";LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        episode(ip,now);
        String id=jdbc.queryForObject("SELECT id FROM siem_ip_blocks WHERE ip_address=?",String.class,ip);
        var user=new com.flarefitness.backend.entity.User();user.setId("practice-admin");user.setUsername("practice-admin");user.setRole("Admin");
        var actor=new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(new com.flarefitness.backend.security.CurrentUserPrincipal(user),null,List.of());
        var request=new SiemPreventionService.RevokeBlock(UUID.randomUUID().toString(),0L,"False positive confirmed after source review.","FALSE_POSITIVE");
        var revoked=prevention.revokeBlock(id,request,actor);
        assertThat(revoked.revokedAt()).isNotNull();assertThat(prevention.revokeBlock(id,request,actor).version()).isEqualTo(revoked.version());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=?",Long.class,ip)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=? AND invalidated_at IS NULL",Long.class,ip)).isZero();
        episode(ip,now.plusMinutes(1));
        assertThat(jdbc.queryForObject("SELECT MAX(strike_number) FROM siem_recurrence_episodes WHERE ip_address=? AND invalidated_at IS NULL",Integer.class,ip)).isEqualTo(1);
    }

    @Test void gatewayWithoutDurableCapabilityCapsFourthEpisodeAtTwentyFourHours() {
        when(gateway.health()).thenReturn(new SiemPreventionGateway.GatewayHealth(true,1,"UP",false));
        String ip="208.67.222.222";
        for(int n=0;n<4;n++)episode(ip,base.plusHours(n*25));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_ip_blocks WHERE ip_address=? AND duration_type='UNTIL_REVOKED'",Long.class,ip)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=?",Long.class,ip)).isEqualTo(4);
    }
}
