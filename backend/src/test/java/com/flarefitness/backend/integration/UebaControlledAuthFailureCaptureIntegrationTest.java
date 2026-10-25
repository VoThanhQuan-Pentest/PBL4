package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.security.TokenFingerprint;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
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
import org.springframework.core.env.Environment;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Explicit env-only opt-in, isolated source capture; no replay, future time, limiter override or model fitting. */
@EnabledIfEnvironmentVariable(named = "UEBA_AUTH_FAILURE_CAPTURE_ENABLED", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false", "siem.security-events.enabled=true",
        "app.security.trusted-proxy-cidrs=", "spring.mail.host=127.0.0.1", "logging.level.AUDIT=OFF"
})
class UebaControlledAuthFailureCaptureIntegrationTest extends ContainerizedIntegrationTest {
    private static final String PASSWORD = "OwnedAuthFailure#LocalOnly1";
    private static final String WRONG_PASSWORD = "WrongOwnedAuthFailure#LocalOnly2";
    private static final String CANARY = "private-auth-failure-agent-must-not-persist";
    private static final long SPACING = Duration.ofMillis(210).toNanos();
    @LocalServerPort private int port;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private ObjectMapper mapper;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    @Autowired private StringRedisTemplate redis;
    @Autowired private Environment environment;
    // Suppress only the source-ID-bearing ordinary file sink, never the controller, limiter, Redis or DB.
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    private final List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> attempts = new ArrayList<>();
    private final Set<String> forbidden = new HashSet<>(Set.of(PASSWORD, WRONG_PASSWORD, CANARY));
    private long lastSendNanos;
    private long minimumSpacingNanos = Long.MAX_VALUE;
    private Instant startedAt;

    @Test
    void captureRealTargetAssociatedAuthFailuresAndPreserveUnattributableThrottle() throws Exception {
        assertThat(environment.getProperty("app.security.login.max-attempts-per-minute", Integer.class)).isEqualTo(5);
        assertThat(environment.getProperty("app.security.login.max-account-attempts-per-minute", Integer.class)).isEqualTo(5);
        String prefix = environment.getRequiredProperty("app.security.login-attempt-prefix");
        String ipKey = prefix + "ip:" + TokenFingerprint.sha256("127.0.0.1");
        // Read-only prerequisite: a fresh owned test environment, not reset/bypass of an existing minute bucket.
        assertThat(redis.hasKey(ipKey)).as("Fresh isolated loopback minute budget required; never reset the limiter").isFalse();
        assertThat(events.count()).as("Dedicated isolated capture must have no pre-existing source events").isZero();
        Path output = ControlledAuthFailureCaptureArtifacts.createFreshPrivateDirectory(projectRoot(),
                System.getenv("UEBA_AUTH_FAILURE_CAPTURE_OUTPUT_DIR"));
        User owned = customer();
        String unknownUsername = "unknown-owned-capture-" + opaqueId();
        forbidden.add(owned.getId()); forbidden.add(owned.getUsername()); forbidden.add(unknownUsername);
        String accountKey = prefix + "account:" + TokenFingerprint.sha256(owned.getUsername());
        assertThat(redis.hasKey(accountKey)).isFalse();
        long jobsBefore = jobs.count();
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        startedAt = Instant.now();
        Instant finishedAt;
        try (HttpClient client = HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build()) {
            HttpResponse<String> csrfResponse = send(client, "CSRF_READ", request("/api/auth/csrf").GET().build());
            assertThat(csrfResponse.statusCode()).isEqualTo(200);
            String csrf = mapper.readTree(csrfResponse.body()).path("token").asText();
            assertThat(csrf).isNotBlank(); forbidden.add(csrf);
            for (int index = 0; index < 4; index++) {
                HttpResponse<String> response = failedLogin(client, csrf, owned.getUsername());
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(mapper.readTree(response.body()).path("code").asText()).isEqualTo("UNAUTHORIZED");
            }
            // Fifth shared-IP reservation remains an unknown failure, with no invented known target.
            assertThat(failedLogin(client, csrf, unknownUsername).statusCode()).isEqualTo(401);
            // This real sixth request is below the total workload bound but must remain HTTP 429 / RATE_LIMITED.
            HttpResponse<String> limited = failedLogin(client, csrf, owned.getUsername());
            assertThat(limited.statusCode()).isEqualTo(429);
            assertThat(mapper.readTree(limited.body()).path("code").asText()).isEqualTo("RATE_LIMITED");
            finishedAt = Instant.now();
            cookies.getCookieStore().getCookies().forEach(cookie -> forbidden.add(cookie.getValue()));
        }
        assertThat(Duration.between(startedAt, finishedAt)).isLessThan(Duration.ofSeconds(60));
        assertThat(redis.opsForValue().get(ipKey)).isEqualTo("6");
        assertThat(redis.opsForValue().get(accountKey)).isEqualTo("5");
        assertThat(redis.getExpire(ipKey, TimeUnit.SECONDS)).isBetween(1L, 60L);
        List<SiemSecurityEvent> captured = events.findAll();
        assertThat(captured).hasSize(6);
        var accountEvidence = events.findAccountEvidence(owned.getId(),
                LocalDateTime.ofInstant(startedAt, ZoneOffset.UTC), LocalDateTime.ofInstant(finishedAt, ZoneOffset.UTC),
                PageRequest.of(0, 100)).getContent();
        assertThat(accountEvidence).hasSize(4).allSatisfy(event -> {
            assertThat(event.getActorUserId()).isNull(); assertThat(event.getTargetUserId()).isEqualTo(owned.getId());
            assertThat(event.getEventType()).isEqualTo("AUTH"); assertThat(event.getAction()).isEqualTo("LOGIN");
            assertThat(event.getOutcome()).isEqualTo("FAILURE");
        });
        assertThat(captured.stream().filter(event -> "RATE_LIMITED".equals(event.getOutcome())).toList())
                .hasSize(1).allSatisfy(event -> {
                    assertThat(event.getActorUserId()).isNull(); assertThat(event.getTargetUserId()).isNull();
                });
        assertThat(ControlledAuthFailureCaptureArtifacts.verifyOpenWindowFeatureCounts(accountEvidence)
                .get("failed_login_count")).isEqualTo(4.0);
        assertThat(windows.countByAccountId(owned.getId())).isZero();
        assertThat(jobs.count()).isEqualTo(jobsBefore);
        assertThat(users.findById(owned.getId()).orElseThrow().getAuthVersion()).isZero();
        ControlledAuthFailureCaptureArtifacts.write(output, mapper, captured, owned.getId(), "account-" + opaqueId(),
                "scenario-" + opaqueId(), startedAt, finishedAt, attempts, minimumSpacingNanos, forbidden);
        try (var artifacts = Files.list(output)) {
            assertThat(artifacts.map(path -> path.getFileName().toString()).toList()).containsExactlyInAnyOrder(
                    ControlledAuthFailureCaptureArtifacts.EVENTS_FILE, ControlledAuthFailureCaptureArtifacts.SCENARIOS_FILE,
                    ControlledAuthFailureCaptureArtifacts.EVIDENCE_FILE, ControlledAuthFailureCaptureArtifacts.ATTEMPTS_FILE);
        }
    }

    private HttpResponse<String> failedLogin(HttpClient client, String csrf, String username) throws Exception {
        return send(client, "LOGIN_POST", request("/api/auth/login").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        Map.of("username", username, "password", WRONG_PASSWORD)))).build());
    }

    private HttpResponse<String> send(HttpClient client, String operation, HttpRequest request) throws Exception {
        if (lastSendNanos != 0) {
            long wait = SPACING - (System.nanoTime() - lastSendNanos);
            if (wait > 0) TimeUnit.NANOSECONDS.sleep(wait);
        }
        assertThat(Duration.between(startedAt, Instant.now())).isLessThan(Duration.ofSeconds(50));
        long now = System.nanoTime();
        if (lastSendNanos != 0) minimumSpacingNanos = Math.min(minimumSpacingNanos, now - lastSendNanos);
        lastSendNanos = now;
        Instant requestedAt = Instant.now();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        attempts.add(new ControlledAuthFailureCaptureArtifacts.HttpAttempt(attempts.size(), requestedAt,
                Instant.now(), operation, response.statusCode()));
        return response;
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "Mozilla/5.0 Firefox/128.0 " + CANARY);
    }

    private User customer() {
        String id = "controlled-private-auth-" + opaqueId();
        User user = new User(); user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(PASSWORD));
        user.setRole("CUSTOMER"); user.setHoTen("Owned isolated auth-failure fixture"); user.setStatus("Hoat dong");
        user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }

    private static String opaqueId() { return UUID.randomUUID().toString().replace("-", ""); }

    private static Path projectRoot() {
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        return Files.isRegularFile(cwd.resolve("backend/pom.xml")) ? cwd : cwd.getParent();
    }
}
