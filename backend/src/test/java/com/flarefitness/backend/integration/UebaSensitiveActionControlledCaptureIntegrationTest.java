package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * Opt-in capture only. No live accounts, external providers, forced clock, aggregation or models.
 * UEBA_SENSITIVE_CONTROLLED_CAPTURE_ENABLED=true and an absolute, fresh direct-child directory in
 * UEBA_SENSITIVE_CONTROLLED_CAPTURE_OUTPUT_DIR=<project>/observability/runtime/<new-directory>.
 */
@EnabledIfEnvironmentVariable(named = "UEBA_SENSITIVE_CONTROLLED_CAPTURE_ENABLED", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false", "siem.security-events.enabled=true",
        "app.security.trusted-proxy-cidrs=", "spring.mail.host=127.0.0.1", "logging.level.AUDIT=OFF"
})
class UebaSensitiveActionControlledCaptureIntegrationTest extends ContainerizedIntegrationTest {
    private static final long SEND_SPACING_NANOS = Duration.ofMillis(210).toNanos();
    private static final String PRIVATE_CANARY = "sensitive-capture-private-query-body-agent-never-export";
    @LocalServerPort private int port;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private ObjectMapper mapper;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    // Disable only the ordinary raw-ID file sink. HTTP, JWT, Redis and persistence remain real.
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    private final Set<String> forbidden = new HashSet<>(Set.of(PRIVATE_CANARY));
    private final List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> attempts = new ArrayList<>();
    private long lastSendNanos;
    private long minimumSpacingNanos = Long.MAX_VALUE;
    private Instant captureStartedAt;

    @Test
    void capturesRealPasswordMutationsAndPreservesRevokedClientAttemptsWithoutInventingAttribution() throws Exception {
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(projectRoot(),
                System.getenv("UEBA_SENSITIVE_CONTROLLED_CAPTURE_OUTPUT_DIR"));
        String initial = privatePassword(); String replacement = privatePassword(); String secondReplacement = privatePassword();
        User benign = customer(initial); User sequence = customer(initial);
        Map<String, String> aliases = new LinkedHashMap<>();
        aliases.put(benign.getId(), "account-" + opaqueId()); aliases.put(sequence.getId(), "account-" + opaqueId());
        List<SensitiveActionControlledCaptureArtifacts.Scenario> scenarios = List.of(
                new SensitiveActionControlledCaptureArtifacts.Scenario(aliases.get(benign.getId()), "scenario-" + opaqueId(),
                        "BENIGN_PASSWORD_CHANGE", "BENIGN", "OWNED_PASSWORD_MAINTENANCE"),
                new SensitiveActionControlledCaptureArtifacts.Scenario(aliases.get(sequence.getId()), "scenario-" + opaqueId(),
                        "CONTROLLED_PASSWORD_CHANGE_SEQUENCE", "UNSCORED_CONTROLLED_SEQUENCE",
                        "OWNED_REPEATED_CHANGE_SESSION_REVOCATION"));
        long jobsBefore = jobs.count();
        captureStartedAt = Instant.now();
        Instant finishedAt;
        try (OwnedClient benignClient = client(aliases.get(benign.getId()));
             OwnedClient sequenceClient = client(aliases.get(sequence.getId()))) {
            login(benignClient, benign, initial); readProfile(benignClient, false);
            changePassword(benignClient, benign, initial, replacement, 1);
            readProfile(benignClient, true); // Preserve the immediate old-session 401, no server identity claim.
            login(benignClient, benign, replacement); readProfile(benignClient, false);

            login(sequenceClient, sequence, initial); readProfile(sequenceClient, false);
            changePassword(sequenceClient, sequence, initial, replacement, 1); readProfile(sequenceClient, true);
            login(sequenceClient, sequence, replacement); readProfile(sequenceClient, false);
            changePassword(sequenceClient, sequence, replacement, secondReplacement, 2); readProfile(sequenceClient, true);
            login(sequenceClient, sequence, secondReplacement); readProfile(sequenceClient, false);
            finishedAt = Instant.now();
        }
        assertThat(attempts.size()).isEqualTo(24);
        assertThat(attempts.stream().filter(attempt -> "LOGIN".equals(attempt.kind())).count()).isEqualTo(5);
        assertThat(attempts.stream().filter(attempt -> "CSRF_REFRESH".equals(attempt.kind())).count()).isEqualTo(3);
        assertThat(attempts.stream().filter(attempt -> "REVOKED_SESSION_ATTEMPT".equals(attempt.kind())).count()).isEqualTo(3);
        assertThat(Duration.between(captureStartedAt, finishedAt)).isLessThanOrEqualTo(Duration.ofSeconds(60));
        List<SiemSecurityEvent> captured = new ArrayList<>();
        captured.addAll(awaitEvents(benign.getId(), 6, finishedAt));
        captured.addAll(awaitEvents(sequence.getId(), 10, finishedAt));
        assertThat(captured.size()).isEqualTo(16);
        assertThat(captured.stream().filter(event -> "AUTH".equals(event.getEventType())).count()).isEqualTo(5);
        assertThat(captured.stream().filter(event -> "HTTP_REQUEST".equals(event.getEventType())).count()).isEqualTo(8);
        assertThat(captured.stream().filter(event -> "DOMAIN_ACTION".equals(event.getEventType())).count()).isEqualTo(3);
        assertThat(captured.stream().anyMatch(event -> Integer.valueOf(401).equals(event.getHttpStatus()))).isFalse();
        assertSessions(captured, benign, 2); assertSessions(captured, sequence, 3);
        assertThat(windows.countByAccountId(benign.getId())).isZero();
        assertThat(windows.countByAccountId(sequence.getId())).isZero();
        assertThat(jobs.count()).isEqualTo(jobsBefore);
        SensitiveActionControlledCaptureArtifacts.write(output, mapper, captured, aliases, scenarios,
                attempts, captureStartedAt, finishedAt, minimumSpacingNanos, forbidden);
    }

    private void login(OwnedClient client, User user, String password) throws Exception {
        readCsrf(client, "CSRF_READ");
        HttpResponse<String> response = send(client, request("/api/auth/login").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", client.csrf).POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        Map.of("username", user.getUsername(), "password", password)))).build(), "LOGIN", "auth", 200);
        assertThat(mapper.readTree(response.body()).has("access_token")).isFalse();
        for (var cookie : client.cookies.getCookieStore().getCookies()) {
            forbidden.add(cookie.getValue());
            if ("access_token".equals(cookie.getName())) {
                // Only a private exclusion sentinel; never export raw JWT claims or jti.
                String payload = new String(Base64.getUrlDecoder().decode(cookie.getValue().split("\\.")[1]), StandardCharsets.UTF_8);
                String jti = mapper.readTree(payload).path("jti").asText();
                assertThat(!jti.isBlank()).isTrue(); forbidden.add(jti);
            }
        }
    }

    private void changePassword(OwnedClient client, User user, String oldPassword, String newPassword, long version) throws Exception {
        // Authentication clears the pre-login token. Obtain a fresh real double-submit token
        // and retain that extra HTTP read, rather than bypassing the real CSRF filter.
        readCsrf(client, "CSRF_REFRESH");
        send(client, request("/api/profile/password").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", client.csrf).PUT(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        new ChangePasswordRequest(oldPassword, newPassword, newPassword)))).build(),
                "CURRENT_SESSION_REQUEST", "profile", 204);
        User changed = users.findById(user.getId()).orElseThrow();
        assertThat(changed.getAuthVersion()).isEqualTo(version);
        assertThat(passwords.matches(newPassword, changed.getPassword())).isTrue();
        assertThat(passwords.matches(oldPassword, changed.getPassword())).isFalse();
    }

    private void readProfile(OwnedClient client, boolean revoked) throws Exception {
        send(client, request("/api/profile?private=" + PRIVATE_CANARY).GET().build(),
                revoked ? "REVOKED_SESSION_ATTEMPT" : "CURRENT_SESSION_REQUEST", "profile", revoked ? 401 : 200);
    }

    private void readCsrf(OwnedClient client, String kind) throws Exception {
        HttpResponse<String> response = send(client, request("/api/auth/csrf").GET().build(), kind, "auth", 200);
        client.csrf = mapper.readTree(response.body()).path("token").asText();
        assertThat(client.csrf).isNotBlank(); forbidden.add(client.csrf);
    }

    private HttpResponse<String> send(OwnedClient client, HttpRequest request, String kind, String route, int expected) throws Exception {
        if (lastSendNanos != 0) {
            long waitNanos = SEND_SPACING_NANOS - (System.nanoTime() - lastSendNanos);
            if (waitNanos > 0) TimeUnit.NANOSECONDS.sleep(waitNanos);
        }
        assertThat(Duration.between(captureStartedAt, Instant.now())).isLessThan(Duration.ofSeconds(60));
        long now = System.nanoTime();
        if (lastSendNanos != 0) minimumSpacingNanos = Math.min(minimumSpacingNanos, now - lastSendNanos);
        lastSendNanos = now; Instant attemptedAt = Instant.now();
        HttpResponse<String> response = client.http.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("Actual %s %s response", kind, request.method()).isEqualTo(expected);
        attempts.add(new SensitiveActionControlledCaptureArtifacts.ClientAttempt(attempts.size(), client.alias,
                attemptedAt, kind, request.method(), route, response.statusCode()));
        return response;
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "Mozilla/5.0 Firefox/128.0 " + PRIVATE_CANARY);
    }
    private User customer(String password) {
        User user = new User(); String id = "sensitive-private-" + opaqueId();
        user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(password)); user.setAuthVersion(0L);
        user.setRole("CUSTOMER"); user.setHoTen("Owned isolated sensitive capture fixture"); user.setStatus("Hoat dong");
        user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC)); forbidden.add(id);
        return users.saveAndFlush(user);
    }
    private String privatePassword() { String value = "LocalCapture#" + opaqueId(); forbidden.add(value); return value; }
    private void assertSessions(List<SiemSecurityEvent> captured, User user, int expectedSessions) {
        var http = captured.stream().filter(event -> user.getId().equals(event.getActorUserId())
                && "HTTP_REQUEST".equals(event.getEventType())).toList();
        assertThat(http.stream().allMatch(event -> event.getSessionPseudonym() != null && event.getSessionIssuedAt() != null)).isTrue();
        assertThat(http.stream().map(SiemSecurityEvent::getSessionPseudonym).distinct().count()).isEqualTo(expectedSessions);
    }
    private List<SiemSecurityEvent> awaitEvents(String actor, int expected, Instant finishedAt) throws InterruptedException {
        List<SiemSecurityEvent> found = List.of();
        for (int attempt = 0; attempt < 100; attempt++) {
            found = events.findAccountEvidence(actor, LocalDateTime.ofInstant(captureStartedAt, ZoneOffset.UTC),
                    LocalDateTime.ofInstant(finishedAt.plusSeconds(1), ZoneOffset.UTC), PageRequest.of(0, 100)).getContent();
            if (found.size() >= expected) break;
            Thread.sleep(20);
        }
        assertThat(found.size()).isEqualTo(expected); return found;
    }
    private static OwnedClient client(String alias) { return new OwnedClient(alias); }
    private static String opaqueId() { return UUID.randomUUID().toString().replace("-", ""); }
    private static Path projectRoot() {
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        return Files.isRegularFile(cwd.resolve("backend/pom.xml")) ? cwd : cwd.getParent();
    }
    private static final class OwnedClient implements AutoCloseable {
        private final String alias;
        private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        private final HttpClient http = HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        private String csrf;
        private OwnedClient(String alias) { this.alias = alias; }
        @Override public void close() { http.close(); }
    }
}
