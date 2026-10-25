package com.flarefitness.backend.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = {
        "app.security.login.max-attempts-per-minute=100",
        "app.security.login.max-account-attempts-per-minute=100"
})
@AutoConfigureMockMvc
class SiemSecurityIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    private String lastCreatedUserId;

    @Test
    void onlyAdminAndAnalystCanUseSiemAndAnalystCannotUseCommerceAdminApis() throws Exception {
        String customer = tokenFor("CUSTOMER");
        String staff = tokenFor("Nhan vien");
        String analyst = tokenFor("Security analyst");
        String socL2 = tokenFor("SOC L2");
        String admin = tokenFor("Quan tri vien");

        mockMvc.perform(get("/api/siem/status").cookie(cookie(customer))).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/siem/incidents/unknown/security-events").cookie(cookie(customer)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/siem/status").cookie(cookie(staff))).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/siem/status").cookie(cookie(analyst))).andExpect(status().isOk());
        mockMvc.perform(get("/api/siem/status").cookie(cookie(socL2))).andExpect(status().isOk());
        mockMvc.perform(get("/api/siem/status").cookie(cookie(admin))).andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/users/page").cookie(cookie(analyst))).andExpect(status().isForbidden());
    }

    @Test
    void authVersionChangeInvalidatesExistingCookieButAllowsNewLogin() throws Exception {
        String token = tokenFor("SOC L2");
        User user = userRepository.findById(lastCreatedUserId).orElseThrow();
        mockMvc.perform(get("/api/siem/status").cookie(cookie(token))).andExpect(status().isOk());

        user.setAuthVersion(user.getAuthVersion() + 1L);
        userRepository.saveAndFlush(user);

        mockMvc.perform(get("/api/siem/status").cookie(cookie(token)))
                .andExpect(status().isUnauthorized());
        String newToken = login(user.getUsername(), "Integration#1");
        mockMvc.perform(get("/api/siem/status").cookie(cookie(newToken))).andExpect(status().isOk());
    }

    @Test
    void modelManagementIsAdminOnlyAndStatusIsVisibleToSoc() throws Exception {
        String l1 = tokenFor("SOC L1");
        String admin = tokenFor("Quan tri vien");
        mockMvc.perform(get("/api/siem/ueba/status").cookie(cookie(l1)))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/siem/ueba/training-jobs").cookie(cookie(l1)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/siem/ueba/training-jobs").cookie(cookie(admin)))
                .andExpect(status().isOk());

        String invalidRange = objectMapper.writeValueAsString(Map.of(
                "from", "2026-09-27T00:00:00", "to", "2026-09-26T00:00:00"));
        String l1Csrf = csrfToken();
        mockMvc.perform(post("/api/siem/ueba/training-jobs")
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", l1Csrf))
                        .header("X-XSRF-TOKEN", l1Csrf)
                        .contentType(MediaType.APPLICATION_JSON).content(invalidRange))
                .andExpect(status().isForbidden());
        String adminCsrf = csrfToken();
        mockMvc.perform(post("/api/siem/ueba/training-jobs")
                        .cookie(cookie(admin), new MockCookie("XSRF-TOKEN", adminCsrf))
                        .header("X-XSRF-TOKEN", adminCsrf)
                        .contentType(MediaType.APPLICATION_JSON).content(invalidRange))
                .andExpect(status().isBadRequest());
    }

    @Test
    void onlyAdminCanDeclareOrEndNoiseSuppressionTestWindows() throws Exception {
        String l1 = tokenFor("SOC L1");
        String admin = tokenFor("Quan tri vien");
        String body = objectMapper.writeValueAsString(Map.of(
                "name", "Authorized owned-lab scanner",
                "starts_at", "2035-01-02T12:00:00",
                "ends_at", "2035-01-02T13:00:00"));
        String l1Csrf = csrfToken();
        mockMvc.perform(post("/api/siem/test-windows")
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", l1Csrf))
                        .header("X-XSRF-TOKEN", l1Csrf)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        String adminCsrf = csrfToken();
        MvcResult created = mockMvc.perform(post("/api/siem/test-windows")
                        .cookie(cookie(admin), new MockCookie("XSRF-TOKEN", adminCsrf))
                        .header("X-XSRF-TOKEN", adminCsrf)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn();
        String id = objectMapper.readTree(created.getResponse().getContentAsString()).path("id").asText();
        long version = objectMapper.readTree(created.getResponse().getContentAsString()).path("version").asLong();
        String endPath = "/api/siem/test-windows/" + id + "/end?version=" + version;
        l1Csrf = csrfToken();
        mockMvc.perform(patch(endPath)
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", l1Csrf))
                        .header("X-XSRF-TOKEN", l1Csrf))
                .andExpect(status().isForbidden());
        adminCsrf = csrfToken();
        mockMvc.perform(patch(endPath)
                        .cookie(cookie(admin), new MockCookie("XSRF-TOKEN", adminCsrf))
                        .header("X-XSRF-TOKEN", adminCsrf))
                .andExpect(status().isOk());
    }

    @Test
    void preventionControlsKeepL1ProposalSeparateFromL2Approval() throws Exception {
        String customer = tokenFor("Khach hang");
        String l1 = tokenFor("SOC L1");
        String l2 = tokenFor("SOC L2");
        mockMvc.perform(get("/api/siem/signatures").cookie(cookie(customer)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/siem/signatures").cookie(cookie(l1)))
                .andExpect(status().isOk());
        String signatureBody = objectMapper.writeValueAsString(Map.of(
                "kind", "PATH_EXACT", "http_method", "GET",
                "match_value", "/.env", "severity", "HIGH"));
        String csrf = csrfToken();
        MvcResult proposed = mockMvc.perform(post("/api/siem/signatures")
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", csrf))
                        .header("X-XSRF-TOKEN", csrf)
                        .contentType(MediaType.APPLICATION_JSON).content(signatureBody))
                .andExpect(status().isOk()).andReturn();
        String id = objectMapper.readTree(proposed.getResponse().getContentAsString()).path("id").asText();
        csrf = csrfToken();
        mockMvc.perform(post("/api/siem/signatures/" + id + "/activate?version=0")
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", csrf))
                        .header("X-XSRF-TOKEN", csrf)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        csrf = csrfToken();
        mockMvc.perform(post("/api/siem/ip-blocks")
                        .cookie(cookie(l1), new MockCookie("XSRF-TOKEN", csrf))
                        .header("X-XSRF-TOKEN", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ip_address", "8.8.8.8", "reason", "Confirmed malicious traffic",
                                "duration_minutes", 15))))
                .andExpect(status().isForbidden());
        csrf = csrfToken();
        mockMvc.perform(post("/api/siem/ip-blocks")
                        .cookie(cookie(l2), new MockCookie("XSRF-TOKEN", csrf))
                        .header("X-XSRF-TOKEN", csrf)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "ip_address", "203.0.113.9", "reason", "Documentation address",
                                "duration_minutes", 15))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/internal/v1/prevention/policy"))
                .andExpect(status().isServiceUnavailable());
    }

    private String tokenFor(String role) throws Exception {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String username = "siem_" + suffix;
        String password = "Integration#1";
        User user = new User();
        user.setId("siem-user-" + suffix);
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setHoTen("SIEM test user");
        user.setEmail(username + "@example.test");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);

        lastCreatedUserId = user.getId();
        return login(username, password);
    }

    private String login(String username, String password) throws Exception {
        String csrfToken = csrfToken();
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(new MockCookie("XSRF-TOKEN", csrfToken))
                        .header("X-XSRF-TOKEN", csrfToken)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", username,
                                "password", password))))
                .andExpect(status().isOk())
                .andReturn();
        String setCookie = login.getResponse().getHeader("Set-Cookie");
        return setCookie.substring(setCookie.indexOf("access_token=") + 13, setCookie.indexOf(';'));
    }

    private String csrfToken() throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf")).andReturn();
        return objectMapper.readTree(csrf.getResponse().getContentAsString()).path("token").asText();
    }

    private MockCookie cookie(String token) {
        return new MockCookie("access_token", token);
    }
}
