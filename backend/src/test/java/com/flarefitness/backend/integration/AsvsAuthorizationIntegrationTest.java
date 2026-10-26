package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

/** Real JWT/Redis/CSRF checks: isolated fixtures, never production accounts or WAF mocks. */
@SpringBootTest
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class AsvsAuthorizationIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    private final java.util.concurrent.atomic.AtomicInteger fixtureAddress = new java.util.concurrent.atomic.AtomicInteger(10);
    private static final String PASSWORD = "AsvsFixture!Password1";
    record Actor(User user, MockCookie cookie) { }

    @TestFactory
    Stream<DynamicTest> roleMatrixRequiresServerAuthorityForEveryProtectedNamespace() throws Exception {
        Map<String, Actor> actors = new LinkedHashMap<>();
        for (String label : new String[]{"Admin", "Staff", "CustomerA", "CustomerB", "L1A", "L1B", "L2A", "L2B"}) {
            String role = label.equals("Admin") ? "Admin" : label.equals("Staff") ? "Nhan vien"
                    : label.startsWith("L1") ? "SOC L1" : label.startsWith("L2") ? "SOC L2" : "Khach hang";
            actors.put(label, actor(role));
        }
        return Stream.concat(actors.entrySet().stream().flatMap(entry ->
                Stream.of("/api/admin/users/page", "/api/orders/page", "/api/siem/status").map(path -> {
                    String label = entry.getKey();
                    boolean allowed = path.contains("/siem/") ? label.equals("Admin") || label.startsWith("L")
                            : path.contains("/admin/") ? label.equals("Admin") : label.equals("Admin") || label.equals("Staff");
                    return DynamicTest.dynamicTest(label + " " + path, () -> mvc.perform(get(path).cookie(entry.getValue().cookie()))
                            .andExpect(allowed ? status().isOk() : status().isForbidden()));
                })), Stream.of("/api/admin/users/page", "/api/orders/page", "/api/siem/status")
                        .map(path -> DynamicTest.dynamicTest("Anonymous " + path,
                                () -> mvc.perform(get(path)).andExpect(status().isUnauthorized()))));
    }

    @Test
    void privateSyncIgnoresForgedOwnershipAndKeepsOtherCustomersStateSeparate() throws Exception {
        Actor a = actor("Khach hang"), b = actor("Khach hang");
        writeCart(a, "[\"owned-by-a\"]", null);
        var before = mapper.readTree(mvc.perform(get("/api/sync/me/cart").cookie(a.cookie()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        int writeStatus = writeCart(b, "[\"owned-by-b\"]", a.user().getId());
        var after = mapper.readTree(mvc.perform(get("/api/sync/me/cart").cookie(a.cookie()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        var ownB = mapper.readTree(mvc.perform(get("/api/sync/me/cart").cookie(b.cookie()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(after).isEqualTo(before);
        assertThat(ownB.path("owner_id").asText()).isEqualTo(b.user().getId());
        if (writeStatus == 200) assertThat(ownB.path("payload").asText()).isEqualTo("[\"owned-by-b\"]");
        else assertThat(ownB.path("payload").isNull() || ownB.path("payload").isMissingNode()).isTrue();
    }

    @Test
    void customerCannotWriteEntitlementsOrSharedStateEvenWithAValidCsrfToken() throws Exception {
        Actor customer = actor("Khach hang"); String csrf = csrf();
        for (String path : new String[]{"/api/sync/me/voucher-assignments", "/api/sync/app/category-registry"}) {
            mvc.perform(put(path).cookie(customer.cookie(), new MockCookie("XSRF-TOKEN", csrf))
                    .header("X-XSRF-TOKEN", csrf).contentType(MediaType.APPLICATION_JSON)
                    .content("{\"payload\":\"[]\"}")).andExpect(status().isForbidden());
        }
    }

    @Test
    void aSessionAloneDoesNotAuthorizeUnsafeRequestsWithoutCsrf() throws Exception {
        Actor customer = actor("Khach hang");
        mvc.perform(put("/api/sync/me/cart").cookie(customer.cookie())
                .contentType(MediaType.APPLICATION_JSON).content("{\"payload\":\"[]\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void publicSearchTreatsSqlSyntaxAsDataAndDoesNotReturnInternalDiagnostics() throws Exception {
        var response = mvc.perform(get("/api/products/query").param("q", "' UNION SELECT password FROM tbl_nguoi_dung --")
                .param("size", "5")).andExpect(status().isOk()).andReturn().getResponse();
        assertThat(mapper.readTree(response.getContentAsString()).path("content").isArray()).isTrue();
        assertThat(response.getContentAsString()).doesNotContain("SQLSyntaxError", "java.sql.", "stackTrace");
    }

    private int writeCart(Actor actor, String payload, String forgedOwner) throws Exception {
        String csrf = csrf();
        var result = mvc.perform(put("/api/sync/me/cart").cookie(actor.cookie(), new MockCookie("XSRF-TOKEN", csrf))
                .header("X-XSRF-TOKEN", csrf).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(forgedOwner == null ? Map.of("payload", payload)
                        : Map.of("payload", payload, "owner_id", forgedOwner))))
                .andReturn();
        int actual = result.getResponse().getStatus();
        if (forgedOwner == null) assertThat(actual).isEqualTo(200);
        else assertThat(actual).isIn(200, 400);
        return actual;
    }

    private Actor actor(String role) throws Exception {
        String id = "asvs-" + UUID.randomUUID();
        User user = new User(); user.setId(id); user.setUsername(id); user.setRole(role);
        user.setPassword(passwords.encode(PASSWORD)); user.setEmail(id + "@example.test");
        user.setHoTen("Isolated ASVS fixture"); user.setStatus("Hoat dong"); user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now()); users.saveAndFlush(user);
        String csrf = csrf();
        var login = mvc.perform(post("/api/auth/login")
                .with(request -> { request.setRemoteAddr("192.0.2." + fixtureAddress.getAndIncrement()); return request; })
                .contentType(MediaType.APPLICATION_JSON)
                .cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .content(mapper.writeValueAsString(Map.of("username", id, "password", PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        String value = login.getResponse().getHeader("Set-Cookie");
        String token = value.substring(value.indexOf("access_token=") + 13, value.indexOf(';'));
        return new Actor(user, new MockCookie("access_token", token));
    }

    private String csrf() throws Exception {
        return mapper.readTree(mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("token").asText();
    }
}
