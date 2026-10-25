package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.siem.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties={"siem.enabled=false","siem.security-events.enabled=true","siem.security-events.post-login-enabled=true",
    "siem.auth.correlation.initial-delay-ms=3600000","siem.ueba.initial-delay-ms=3600000","siem.postlogin.enabled=false",
    "app.security.login.max-attempts-per-minute=100","app.security.login.max-account-attempts-per-minute=100"})
@AutoConfigureMockMvc
class AuthInvestigationIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired MockMvc http;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired JdbcTemplate jdbc;
    @Autowired SiemAuthCorrelationService correlation;
    @Autowired SiemSecurityEventRepository events;
    @Autowired AccountBehaviorAggregationWorker aggregation;
    User user(String role){var u=new User();String id="auth42-"+UUID.randomUUID().toString().substring(0,12);u.setId(id);u.setUsername(id);u.setPassword(encoder.encode("Integration#1"));u.setRole(role);u.setHoTen("Owned auth investigation integration");u.setEmail(id+"@example.test");u.setStatus("Hoat dong");u.setDeleted(false);u.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));return users.saveAndFlush(u);}
    String csrf()throws Exception{return json.readTree(http.perform(get("/api/auth/csrf")).andReturn().getResponse().getContentAsString()).path("token").asText();}
    String login(User user)throws Exception {String csrf=csrf();String cookie=http.perform(post("/api/auth/login").cookie(new MockCookie("XSRF-TOKEN",csrf)).header("X-XSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("username",user.getUsername(),"password","Integration#1")))).andExpect(status().isOk()).andReturn().getResponse().getHeader("Set-Cookie");return cookie.substring(cookie.indexOf("access_token=")+13,cookie.indexOf(';'));}
    @Test void onlyAdminCanChangePolicyWithIdempotencyAndVersionChecks()throws Exception {
        String l1=login(user("SOC L1")),admin=login(user("Quan tri vien"));var policy=correlation.policy();
        Map<String,Object> request=Map.of("mode","OBSERVE","expected_version",policy.version(),"request_id",UUID.randomUUID().toString(),"reason","Owned integration verifies observation-only auth policy.");
        String csrf=csrf();
        http.perform(put("/api/siem/auth-correlation/policy").cookie(new MockCookie("access_token",l1),new MockCookie("XSRF-TOKEN",csrf)).header("X-XSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(request))).andExpect(status().isForbidden());
        String body=json.writeValueAsString(request);
        for(int i=0;i<2;i++){csrf=csrf();http.perform(put("/api/siem/auth-correlation/policy").cookie(new MockCookie("access_token",admin),new MockCookie("XSRF-TOKEN",csrf)).header("X-XSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());}
        assertThat(correlation.policy().version()).isEqualTo(policy.version()+1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_auth_policy_requests WHERE request_id=?",Long.class,request.get("request_id"))).isEqualTo(1);
        var changed=new HashMap<>(request);changed.put("mode","ALERT");csrf=csrf();
        http.perform(put("/api/siem/auth-correlation/policy").cookie(new MockCookie("access_token",admin),new MockCookie("XSRF-TOKEN",csrf)).header("X-XSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(changed))).andExpect(status().isConflict());
        assertThat(correlation.policyHistory()).anyMatch(row->"OBSERVE".equals(row.get("mode"))&&row.get("reason").equals(request.get("reason")));
    }
    @Test void concurrentWorkersAndReplayProduceOneEpisodeAndNoSignatureStrike()throws Exception {
        User target=user("CUSTOMER");jdbc.update("UPDATE siem_auth_correlation_policy SET mode='ALERT',version=version+1 WHERE id=1");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);List<String> ids=new ArrayList<>();
        for(int i=0;i<6;i++){
            var e=new SiemSecurityEvent();e.setId(UUID.randomUUID().toString());e.setAuthRequestId(UUID.randomUUID().toString());e.setEventTimestamp(now.minusSeconds(90-i*10));e.setCreatedAt(e.getEventTimestamp());e.setEventType("AUTH");e.setAction("LOGIN");e.setOutcome(i==5?"SUCCESS":"FAILURE");e.setTargetUserId(target.getId());e.setActorUserId(i==5?target.getId():null);e.setSourceIp("192.0.2.25");e.setUserAgentFamily("CHROMIUM");events.saveAndFlush(e);ids.add(e.getId());
        }
        Long strikes=jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes",Long.class);
        ExecutorService pool=Executors.newFixedThreadPool(2);
        try{var one=pool.submit(correlation::process);var two=pool.submit(correlation::process);one.get(30,TimeUnit.SECONDS);two.get(30,TimeUnit.SECONDS);}finally{pool.shutdownNow();}
        correlation.process();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_incidents WHERE target_user_id=? AND rule_id='AUTH_BRUTE_TARGET'",Long.class,target.getId())).isEqualTo(1);
        var incident=jdbc.queryForMap("SELECT id,first_seen,last_seen FROM siem_incidents WHERE target_user_id=? AND rule_id='AUTH_BRUTE_TARGET'",target.getId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_auth_finding_events e JOIN siem_auth_findings f ON f.id=e.finding_id WHERE f.incident_id=?",Long.class,incident.get("id"))).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes",Long.class)).isEqualTo(strikes);
        assertThat(incident.get("first_seen")).isNotEqualTo(incident.get("last_seen"));
        assertThat(jdbc.queryForObject("SELECT severity FROM siem_incidents WHERE id=?",String.class,incident.get("id"))).isEqualTo("HIGH");
    }
    @Test void newInvestigationEventsRemainVisibleWithoutChangingBaselineWindows(){
        User target=user("CUSTOMER");LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);var e=new SiemSecurityEvent();e.setId(UUID.randomUUID().toString());e.setAuthRequestId(UUID.randomUUID().toString());e.setEventTimestamp(now.minusMinutes(30));e.setCreatedAt(e.getEventTimestamp());e.setEventType("AUTH_INVESTIGATION");e.setAction("OTP_CHECK");e.setOutcome("FAILURE");e.setActorUserId(target.getId());e.setTargetUserId(target.getId());e.setSourceIp("192.0.2.26");events.saveAndFlush(e);
        var page=org.springframework.data.domain.PageRequest.of(0,100);
        assertThat(events.findAccountWindow(target.getId(),now.minusHours(1),now,page).getContent()).isEmpty();
        assertThat(events.findAccountEvidence(target.getId(),now.minusHours(1),now,page).getContent()).extracting(SiemSecurityEvent::getId).contains(e.getId());
        aggregation.aggregatePendingAt(now.plusHours(1));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_account_behavior_windows WHERE account_id=?",Long.class,target.getId())).isZero();
    }
}
