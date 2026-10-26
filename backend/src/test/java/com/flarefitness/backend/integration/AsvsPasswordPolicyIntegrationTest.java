package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.service.AuthService;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Actual Admin API and persisted BCrypt; OTP login has its separate enabled-profile regression suite. */
@SpringBootTest(properties = "app.security.login-otp-enabled=false")
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class AsvsPasswordPolicyIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired AuthService auth;
    @Autowired PasswordEncoder passwords;
    private MockCookie administrator;

    @BeforeEach void administrator() {
        String id = "asvs-pw-admin-" + UUID.randomUUID();
        User admin = new User(); admin.setId(id); admin.setUsername(id); admin.setRole("Admin");
        admin.setPassword(passwords.encode("Synthetic!AdministratorPW1")); admin.setEmail(id + "@example.test");
        admin.setHoTen("Synthetic administrator"); admin.setStatus("Hoat dong");
        admin.setDeleted(false); admin.setCreatedAt(LocalDateTime.now()); users.saveAndFlush(admin);
        administrator = new MockCookie("access_token", auth.login(new LoginRequest(id, "Synthetic!AdministratorPW1"),
                "192.0.2.171", "ASVS password fixture").accessToken());
    }

    @Test void administratorCanProvisionAPassphraseWithoutCompositionRulesAndSpacesRemainSignificant() throws Exception {
        String username = username(); String raw = "  amber rivers cross silent hills  ";
        create(username, raw).andExpect(status().isCreated());
        User created = users.findByUsernameIgnoreCase(username).orElseThrow();
        assertThat(passwords.matches(raw, created.getPassword())).isTrue();
        assertThat(passwords.matches(raw.trim(), created.getPassword())).isFalse();
        assertThat(auth.login(new LoginRequest(username, raw), "192.0.2.172", "ASVS password fixture").user().id()).isEqualTo(created.getId());
    }

    @Test void commonOrContextPasswordsCannotCreateAnAccount() throws Exception {
        for (String password : new String[]{"123456789012", "FlareFitness2026!", "PBL4 password 2026"}) {
            String username = username(); create(username, password).andExpect(status().isBadRequest());
            assertThat(users.existsByUsernameIgnoreCase(username)).isFalse();
        }
    }

    @Test void a128CharacterSupplementaryUnicodePasswordCanBeCreatedAndUsedAtTheHttpBoundary() throws Exception {
        String username = username(); String password = "🐚".repeat(128);
        create(username, password).andExpect(status().isCreated());
        String csrf = csrf();
        mvc.perform(post("/api/auth/login").with(request -> { request.setRemoteAddr("192.0.2.173"); return request; })
                .cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("username", username, "password", password))))
                .andExpect(status().isOk());
        String shortName = username(); create(shortName, "🐚".repeat(6)).andExpect(status().isBadRequest());
        assertThat(users.existsByUsernameIgnoreCase(shortName)).isFalse();
    }

    @Test void changingAnAdministrativePasswordAlsoPreservesSpacesAndRevokesTheOldCredential() throws Exception {
        String username = username(); create(username, "amber rivers cross silent hills").andExpect(status().isCreated());
        User user = users.findByUsernameIgnoreCase(username).orElseThrow();
        String replacement = "  quiet silver valleys beyond dawn  "; String csrf = csrf();
        mvc.perform(put("/api/admin/users/" + user.getId()).cookie(administrator, new MockCookie("XSRF-TOKEN", csrf))
                .header("X-XSRF-TOKEN", csrf).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload(username, replacement))))
                .andExpect(status().isOk());
        User updated = users.findActiveById(user.getId()).orElseThrow();
        assertThat(passwords.matches(replacement, updated.getPassword())).isTrue();
        assertThat(passwords.matches(replacement.trim(), updated.getPassword())).isFalse();
        assertThat(updated.getAuthVersion()).isGreaterThan(user.getAuthVersion());
    }

    private org.springframework.test.web.servlet.ResultActions create(String username, String password) throws Exception {
        String csrf = csrf();
        return mvc.perform(post("/api/admin/users").cookie(administrator, new MockCookie("XSRF-TOKEN", csrf))
                .header("X-XSRF-TOKEN", csrf).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(payload(username, password))));
    }
    private Map<String, String> payload(String username, String password) {
        return Map.of("username", username, "ho_ten", "Synthetic passphrase fixture", "email", username + "@example.test",
                "role", "Nhan vien", "status", "Hoat dong", "password", password);
    }
    private String csrf() throws Exception {
        MvcResult result = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        return mapper.readTree(result.getResponse().getContentAsString()).path("token").asText();
    }
    private String username() { return "asvs-pw-" + UUID.randomUUID(); }
}
