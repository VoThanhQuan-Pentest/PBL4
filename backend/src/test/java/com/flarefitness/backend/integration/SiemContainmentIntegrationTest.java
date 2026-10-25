package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.security.*;
import com.flarefitness.backend.service.AuthService;
import com.flarefitness.backend.service.siem.SiemContainmentService;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;

@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
@SpringBootTest(properties={"app.security.login.max-attempts-per-minute=100","app.security.login.max-account-attempts-per-minute=100"})
class SiemContainmentIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired SiemContainmentService containment;
    @Autowired org.springframework.test.web.servlet.MockMvc http;
    @Autowired UserRepository users;
    @Autowired SiemIncidentRepository incidents;
    @Autowired PasswordEncoder passwords;
    @Autowired AuthService auth;
    @Autowired JwtTokenService jwt;
    @Autowired RedisTokenStore tokens;
    private User user(String role) {
        User u=new User();u.setId(UUID.randomUUID().toString());u.setUsername("practice-"+UUID.randomUUID());u.setRole(role);
        u.setPassword(passwords.encode("Practice#1234"));u.setHoTen("SOC-PRACTICE");u.setStatus("Hoat dong");u.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(u);
    }
    private UsernamePasswordAuthenticationToken principal(User user) {return new UsernamePasswordAuthenticationToken(new CurrentUserPrincipal(user),null,new CurrentUserPrincipal(user).getAuthorities());}
    private SiemIncident incident(User actor,User target) {
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        SiemIncident i=new SiemIncident();i.setId(UUID.randomUUID().toString());i.setGroupingKey("practice:"+UUID.randomUUID());i.setTitle("SOC-PRACTICE isolation");
        i.setTargetUserId(target.getId());i.setAssigneeUserId(actor.getId());i.setOrigin(IncidentOrigin.UEBA);i.setQueueTier(IncidentQueueTier.L2);i.setStatus(IncidentStatus.IN_PROGRESS);
        i.setSourceSeverity("high");i.setSeverity(IncidentSeverity.HIGH);i.setScore(90);i.setClassification(IncidentClassification.INVESTIGATE);i.setClassificationReason("Practice; not live detection");
        i.setConclusion(IncidentConclusion.UNREVIEWED);i.setCreatedAt(now);i.setFirstSeen(now);i.setLastSeen(now);i.setUpdatedAt(now);i.setBucketStart(now);
        return incidents.saveAndFlush(i);
    }
    @Test void apiRejectsL1ResponseActionsAndArbitraryEvidenceStreams() throws Exception {
        var l1=principal(user("SOC L1"));
        String csrf=new com.fasterxml.jackson.databind.ObjectMapper().readTree(http.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/auth/csrf")).andReturn().getResponse().getContentAsString()).path("token").asText();
        String body="{\"request_id\":\"practice-api\",\"expected_version\":0,\"reason\":\"Investigating a customer account.\",\"duration\":\"15_MINUTES\"}";
        http.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/siem/incidents/unknown/containment-actions")
            .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication(l1))
            .cookie(new org.springframework.mock.web.MockCookie("XSRF-TOKEN",csrf)).header("X-XSRF-TOKEN",csrf)
            .contentType(org.springframework.http.MediaType.APPLICATION_JSON).content(body))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
        http.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/siem/evidence")
            .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication(l1))
            .param("from","2026-10-23T00:00:00").param("to","2026-10-24T00:00:00").param("dataset",".security"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest());
    }

    @Test void isolationIsVersionedIdempotentAndReleaseDoesNotRestoreOldTokens() {
        User actor=user("SOC L2"),target=user("CUSTOMER");SiemIncident incident=incident(actor,target);
        var old=auth.login(new LoginRequest(target.getUsername(),"Practice#1234"),"127.0.0.1","integration");
        long oldVersion=jwt.extractAuthVersion(old.accessToken());
        var request=new SiemContainmentService.Request(UUID.randomUUID().toString(),incident.getVersion(),"Confirmed customer isolation in practice case.","UNTIL_REVOKED");
        var action=containment.isolate(incident.getId(),request,principal(actor));
        assertThat(action.status()).isEqualTo("APPLIED");assertThat(action.expiresAt()).isNull();
        assertThat(containment.isolate(incident.getId(),request,principal(actor)).id()).isEqualTo(action.id());
        User isolated=users.findById(target.getId()).orElseThrow();assertThat(isolated.isSocIsolationActive()).isTrue();
        assertThat(isolated.getAuthVersion()).isGreaterThan(oldVersion);assertThat(new CurrentUserPrincipal(isolated).isAccountNonLocked()).isFalse();
        assertThatThrownBy(()->auth.login(new LoginRequest(target.getUsername(),"Practice#1234"),"127.0.0.1","integration")).isInstanceOf(RuntimeException.class);
        var release=new SiemContainmentService.Release(UUID.randomUUID().toString(),action.version(),"Recovery checks passed; allow new login.");
        assertThat(containment.release(action.id(),release,principal(actor)).status()).isEqualTo("RELEASED");
        assertThat(containment.release(action.id(),release,principal(actor)).status()).isEqualTo("RELEASED");
        User released=users.findById(target.getId()).orElseThrow();assertThat(released.isSocIsolationActive()).isFalse();
        assertThat(released.getAuthVersion()).isGreaterThan(oldVersion);
        assertThat(tokens.findUsername(old.accessToken())).isNull();
        assertThat(auth.login(new LoginRequest(target.getUsername(),"Practice#1234"),"127.0.0.1","integration").user().id()).isEqualTo(target.getId());
    }
    @Test void l1WrongAssigneeProtectedTargetAndStaleVersionAreRejected() {
        User actor=user("SOC L2"),customer=user("CUSTOMER"),l1=user("SOC L1"),other=user("SOC L2");
        SiemIncident incident=incident(actor,customer);
        var request=new SiemContainmentService.Request(UUID.randomUUID().toString(),incident.getVersion(),"Investigating account containment.","15_MINUTES");
        assertThatThrownBy(()->containment.isolate(incident.getId(),request,principal(l1))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(()->containment.isolate(incident.getId(),request,principal(other))).isInstanceOf(AccessDeniedException.class);
        var stale=new SiemContainmentService.Request(UUID.randomUUID().toString(),999L,request.reason(),request.duration());
        assertThatThrownBy(()->containment.isolate(incident.getId(),stale,principal(actor))).isInstanceOf(ConflictException.class);
        SiemIncident protectedCase=incident(actor,other);
        assertThatThrownBy(()->containment.isolate(protectedCase.getId(),new SiemContainmentService.Request(UUID.randomUUID().toString(),protectedCase.getVersion(),request.reason(),"UNTIL_REVOKED"),principal(actor))).isInstanceOf(AccessDeniedException.class);
        assertThat(users.findById(customer.getId()).orElseThrow().isSocIsolationActive()).isFalse();
    }
}
