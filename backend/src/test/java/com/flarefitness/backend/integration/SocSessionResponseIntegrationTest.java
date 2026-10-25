package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemResponseActionRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuthService;
import com.flarefitness.backend.service.siem.SiemResponseActionService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "app.security.login.max-attempts-per-minute=100",
        "app.security.login.max-account-attempts-per-minute=100"
})
@AutoConfigureMockMvc
class SocSessionResponseIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private UserRepository users;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private SiemResponseActionRepository actions;
    @Autowired private PasswordEncoder passwords;
    @Autowired private AuthService authService;
    @Autowired private SiemResponseActionService responseActions;
    @Autowired private MockMvc mockMvc;

    @Test
    void onlyAssignedL2CanRevokeAndOldCustomerJwtStopsWorking() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        User customer = user("customer-" + suffix, "customer_" + suffix, "Khach hang");
        User l1 = user("l1-" + suffix, "l1_" + suffix, "SOC L1");
        User l2 = user("l2-" + suffix, "l2_" + suffix, "SOC L2");
        String oldToken = authService.login(new LoginRequest(customer.getUsername(), "Integration#1"),
                "127.0.0.1").accessToken();
        mockMvc.perform(get("/api/auth/me").cookie(new MockCookie("access_token", oldToken)))
                .andExpect(status().isOk());

        SiemIncident incident = new SiemIncident();
        incident.setId("ueba-response-" + suffix);
        incident.setGroupingKey("ueba-response-group-" + suffix);
        incident.setServiceId("flare-web");
        incident.setRuleId("FLARE_UEBA_ACCOUNT_ANOMALY");
        incident.setSourceIp("203.0.113.55");
        incident.setQueueTier(IncidentQueueTier.L2);
        incident.setOrigin(IncidentOrigin.UEBA);
        incident.setTargetUserId(customer.getId());
        incident.setBucketStart(LocalDateTime.now(ZoneOffset.UTC).minusHours(1));
        incident.setTitle("Suspected customer account takeover");
        incident.setSourceSeverity("high");
        incident.setScore(80);
        incident.setSeverity(IncidentSeverity.HIGH);
        incident.setClassification(IncidentClassification.INVESTIGATE);
        incident.setClassificationReason("Independent behavioral indicators");
        incident.setMissingData(false);
        incident.setStatus(IncidentStatus.IN_PROGRESS);
        incident.setConclusion(IncidentConclusion.UNREVIEWED);
        incident.setAssigneeUserId(l2.getId());
        incident.setManualInvestigateOverride(false);
        incident.setAlertCount(1);
        incident.setDistinctRuleCount(1);
        incident.setFirstSeen(incident.getBucketStart());
        incident.setLastSeen(incident.getBucketStart().plusMinutes(15));
        incident.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        incident.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        incidents.saveAndFlush(incident);
        SiemDtos.RevokeSessions request = new SiemDtos.RevokeSessions(incident.getVersion(),
                "ueba-revoke-" + suffix, "Confirmed account takeover indicators");

        assertThatThrownBy(() -> responseActions.revokeCustomerSessions(
                incident.getId(), request, principal(l1))).isInstanceOf(AccessDeniedException.class);
        assertThat(users.findById(customer.getId()).orElseThrow().getAuthVersion()).isZero();

        SiemDtos.SessionRevocationResult result = responseActions.revokeCustomerSessions(
                incident.getId(), request, principal(l2));
        assertThat(result.newAuthVersion()).isEqualTo(1);
        assertThat(actions.findByRequestId(request.requestId())).isPresent();
        assertThat(responseActions.revokeCustomerSessions(incident.getId(), request, principal(l2)).id())
                .isEqualTo(result.id());
        assertThat(users.findById(customer.getId()).orElseThrow().getAuthVersion()).isEqualTo(1);

        mockMvc.perform(get("/api/auth/me").cookie(new MockCookie("access_token", oldToken)))
                .andExpect(status().isUnauthorized());
        String newToken = authService.login(new LoginRequest(customer.getUsername(), "Integration#1"),
                "127.0.0.1").accessToken();
        mockMvc.perform(get("/api/auth/me").cookie(new MockCookie("access_token", newToken)))
                .andExpect(status().isOk());
    }

    private User user(String id, String username, String role) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setPassword(passwords.encode("Integration#1"));
        user.setRole(role);
        user.setHoTen("SOC response fixture");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }

    private UsernamePasswordAuthenticationToken principal(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
