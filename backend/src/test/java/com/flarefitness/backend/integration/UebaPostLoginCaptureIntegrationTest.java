package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.siem.PostLoginBehaviorFeatures;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Real HTTP/JWT/Redis/MySQL. OTP transport is mocked; never a detection-quality or blocking proof. */
@EnabledIfSystemProperty(named = "postlogin.capture.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false",
        "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
        "app.security.trusted-proxy-cidrs=", "spring.mail.host=127.0.0.1", "logging.level.AUDIT=OFF"
})
class UebaPostLoginCaptureIntegrationTest extends ContainerizedIntegrationTest {
    @LocalServerPort private int port;
    @Autowired private ObjectMapper json;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private SiemSecurityEventRepository events;
    @MockitoBean private EmailOtpService otp;
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    private final List<String> excluded = new ArrayList<>();

    @Test @Timeout(120)
    void realSessionsAssociateAttemptsBeforeMutationsAndFailedAttemptSurvivesRollback() throws Exception {
        Path repo = Path.of("").toAbsolutePath().normalize();
        if (!Files.isRegularFile(repo.resolve("backend/pom.xml"))) repo = repo.getParent();
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(repo,
                System.getProperty("postlogin.capture.output"));
        String initial = "OwnedInitial#" + UUID.randomUUID();
        String replacement = "OwnedReplacement#" + UUID.randomUUID();
        excluded.add(initial); excluded.add(replacement);
        User owner = customer(initial), other = customer(initial);
        LocalDateTime from = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1);
        try (Client a = new Client(); Client b = new Client(); Client c = new Client()) {
            login(a, owner, initial); login(b, owner, initial);
            send(a, "GET", "/api/profile", null, 200); send(b, "GET", "/api/profile", null, 200);
            csrf(a);
            send(a, "PUT", "/api/profile", new UpdateProfileRequest("Owned fixture", "new-" + UUID.randomUUID() + "@example.test",
                    "093" + String.format("%07d", Math.floorMod(UUID.randomUUID().hashCode(), 10_000_000)), "123456"), 200);
            csrf(a);
            send(a, "PUT", "/api/profile/password", new ChangePasswordRequest(initial, replacement, replacement), 204);
            send(b, "GET", "/api/profile", null, 401);
            login(c, other, initial); csrf(c);
            send(c, "PUT", "/api/profile/password", new ChangePasswordRequest("incorrect-current", replacement, replacement), 400);
        }
        LocalDateTime to = LocalDateTime.now(ZoneOffset.UTC).plusSeconds(1);
        List<SiemSecurityEvent> ownerEvents = evidence(owner, from, to), otherEvents = evidence(other, from, to);
        var logins = ownerEvents.stream().filter(e -> "AUTH".equals(e.getEventType())).toList();
        var attempts = ownerEvents.stream().filter(e -> "SENSITIVE_ACTION_ATTEMPT".equals(e.getEventType())).toList();
        var actions = ownerEvents.stream().filter(e -> "DOMAIN_ACTION".equals(e.getEventType())).toList();
        assertThat(logins).hasSize(2); assertThat(attempts).hasSize(2); assertThat(actions).hasSize(2);
        assertThat(logins).extracting(SiemSecurityEvent::getSessionPseudonym).doesNotHaveDuplicates();
        assertThat(attempts).allSatisfy(e -> assertThat(e.getSessionPseudonym()).isEqualTo(logins.get(0).getSessionPseudonym()));
        assertThat(actions).allSatisfy(e -> assertThat(e.getSessionPseudonym()).isEqualTo(logins.get(0).getSessionPseudonym()));
        var passwordAttempt = attempts.stream().filter(e -> "PASSWORD_CHANGE".equals(e.getAction())).findFirst().orElseThrow();
        var passwordAction = actions.stream().filter(e -> "PASSWORD_CHANGE".equals(e.getAction())).findFirst().orElseThrow();
        assertThat(passwordAttempt.getEventTimestamp()).isBefore(passwordAction.getEventTimestamp());
        var snapshot = PostLoginBehaviorFeatures.beforeAttempt(passwordAttempt, ownerEvents);
        assertThat(snapshot.values().get(2)).isEqualTo(1);
        assertThat(snapshot.values().get(3)).isEqualTo(1);
        assertThat(snapshot.values().get(7)).isEqualTo(1); // Earlier email change only; current password outcome excluded.
        assertThat(snapshot.values().get(8)).isZero();
        assertThat(snapshot.values().get(9)).isEqualTo(1);
        assertThat(snapshot.values().get(14)).isEqualTo(1); // Parallel legitimate session remains distinct.
        assertThat(otherEvents.stream().filter(e -> "SENSITIVE_ACTION_ATTEMPT".equals(e.getEventType())).count()).isEqualTo(1);
        assertThat(otherEvents.stream().filter(e -> "DOMAIN_ACTION".equals(e.getEventType())).count()).isZero();
        assertThat(passwords.matches(initial, users.findById(other.getId()).orElseThrow().getPassword())).isTrue();
        assertThat(passwords.matches(replacement, users.findById(owner.getId()).orElseThrow().getPassword())).isTrue();
        var all = new ArrayList<>(ownerEvents); all.addAll(otherEvents);
        var association = all.stream().filter(e -> !"HTTP_REQUEST".equals(e.getEventType())).toList();
        assertThat(association).allSatisfy(e -> {
            assertThat(e.getTelemetryContractVersion()).isEqualTo(4);
            assertThat(e.getSessionPseudonym()).matches("[0-9a-f]{64}");
        });
        var captured = new ArrayList<Map<String, Object>>();
        int index = 0;
        for (var event : all) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("event_id", "owned-event-" + index++);
            value.put("actor_user_id", owner.getId().equals(event.getActorUserId()) ? "owned-account-a" : "owned-account-b");
            value.put("event_type", event.getEventType()); value.put("action", event.getAction()); value.put("outcome", event.getOutcome());
            value.put("event_timestamp", event.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());
            value.put("telemetry_contract_version", event.getTelemetryContractVersion());
            value.put("session_pseudonym", event.getSessionPseudonym());
            value.put("session_issued_at", event.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
            if (event.getHttpStatus() != null) value.put("http_status", event.getHttpStatus());
            if (event.getEndpointCategory() != null) value.put("endpoint_category", event.getEndpointCategory());
            captured.add(value);
        }
        String payload = json.writeValueAsString(Map.of("data_provenance", "OWNED_CONTROLLED_LOCAL_HTTP", "events", captured));
        for (String secret : excluded) assertThat(payload).doesNotContain(secret);
        Path capture = output.resolve("server-events.private.json");
        Files.writeString(capture, payload + "\n", StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(capture, PosixFilePermissions.fromString("rw-------"));
        var receipt = Map.of("status", "CAPTURE_PARITY_PASS", "real_http_jwt_redis_mysql", true,
                "email_otp_mocked", true, "fixture_accounts", 2, "successful_logins", 3,
                "sensitive_attempts", 3, "completed_sensitive_actions", 2, "additional_fit_calls", 0,
                "holdout_scored", false, "auto_containment", false);
        Path receiptPath = output.resolve("capture-test.private.json");
        Files.writeString(receiptPath, json.writeValueAsString(receipt) + "\n", StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(receiptPath, PosixFilePermissions.fromString("rw-------"));
    }

    private List<SiemSecurityEvent> evidence(User user, LocalDateTime from, LocalDateTime to) {
        return events.findAccountEvidence(user.getId(), from, to, PageRequest.of(0, 100)).getContent().stream()
                .sorted(Comparator.comparing(SiemSecurityEvent::getEventTimestamp)).toList();
    }

    private User customer(String password) {
        var user = new User(); String id = "postlogin-" + UUID.randomUUID().toString().replace("-", "");
        user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(password)); user.setAuthVersion(0L);
        user.setRole("CUSTOMER"); user.setHoTen("Owned postlogin fixture"); user.setEmail(id + "@example.test");
        user.setStatus("Hoat dong"); user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        excluded.add(id);
        return users.saveAndFlush(user);
    }

    private void login(Client client, User user, String password) throws Exception {
        csrf(client); send(client, "POST", "/api/auth/login", Map.of("username", user.getUsername(), "password", password), 200);
        client.cookies.getCookieStore().getCookies().forEach(cookie -> excluded.add(cookie.getValue()));
    }

    private void csrf(Client client) throws Exception {
        var response = send(client, "GET", "/api/auth/csrf", null, 200);
        client.csrf = json.readTree(response.body()).path("token").asText();
    }

    private HttpResponse<String> send(Client client, String method, String path, Object body, int status) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(10))
                .header("X-Request-ID", "deliberately-reused-client-trace").header("User-Agent", "OwnedPostloginFixture/1.0");
        if (body == null) request.method(method, HttpRequest.BodyPublishers.noBody());
        else request.header("Content-Type", "application/json").header("X-XSRF-TOKEN", client.csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        var response = client.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(method + " " + path).isEqualTo(status);
        return response;
    }

    private static final class Client implements AutoCloseable {
        final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        final HttpClient http = HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        String csrf;
        @Override public void close() { http.close(); }
    }
}
