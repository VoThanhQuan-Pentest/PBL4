package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * Explicit opt-in source capture, not a replay/closed-window/ML qualification test.
 * Only owned ephemeral users, loopback HTTP and the inherited Testcontainers MySQL/Redis are used.
 * Run with -Dueba.controlled.capture.enabled=true and an absolute, fresh
 * -Dueba.controlled.capture.output-dir=<project>/observability/runtime/<new-directory>.
 */
@EnabledIfSystemProperty(named = "ueba.controlled.capture.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1",
        "siem.enabled=false", "siem.ueba.enabled=false", "siem.prevention.enabled=false",
        "siem.prevention.demo-enabled=false", "siem.security-events.enabled=true",
        "app.security.trusted-proxy-cidrs=", "spring.mail.host=127.0.0.1", "logging.level.AUDIT=OFF"
})
class UebaControlledTraceCaptureIntegrationTest extends ContainerizedIntegrationTest {
    private static final String PASSWORD = "ControlledCapture#LocalOnly1";
    private static final String CANARY = "private-controlled-query-body-agent-must-not-persist";
    private static final long SEND_SPACING_NANOS = Duration.ofMillis(210).toNanos();
    @LocalServerPort private int port;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private ObjectMapper mapper;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    // The ordinary outbox exporter includes source user IDs. Disable only that file sink:
    // capture still uses the real HTTP controller, JWT verification, Redis allowlist and DB.
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;

    private long lastSendNanos;
    private long minimumSpacingNanos = Long.MAX_VALUE;
    private Instant captureStartedAt;
    private int clientRequests;
    private int loginCount;
    private final Map<Integer, Long> clientHttpStatuses = new TreeMap<>();
    private final Set<String> forbidden = new HashSet<>(Set.of(PASSWORD, CANARY));

    @Test
    void captureOwnedServerTelemetryWithoutInventingSessionsOrElapsedWindowClosure() throws Exception {
        Path output = ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(projectRoot(),
                System.getProperty("ueba.controlled.capture.output-dir"));
        List<User> owned = List.of(customer(), customer(), customer(), customer());
        Map<String, String> accountAliases = new LinkedHashMap<>();
        for (User user : owned) {
            accountAliases.put(user.getId(), "account-" + opaqueId());
            forbidden.add(user.getId()); forbidden.add(user.getUsername());
        }
        // Workload plans never receive labels. Labels live only in a separate metadata file.
        List<ControlledTraceCaptureArtifacts.Scenario> scenarios = List.of(
                scenario(accountAliases.get(owned.get(0).getId()), "NORMAL_BROWSING", "BENIGN"),
                scenario(accountAliases.get(owned.get(1).getId()), "NORMAL_POLLING", "BENIGN"),
                scenario(accountAliases.get(owned.get(2).getId()), "BOUNDED_BENIGN_BURST", "BENIGN"),
                scenario(accountAliases.get(owned.get(3).getId()), "OWNED_ENDPOINT_SCAN", "OWNED_ENDPOINT_SCAN"));
        long modelJobsBefore = jobs.count();
        List<OwnedClient> clients = new ArrayList<>();
        captureStartedAt = Instant.now();
        Instant finishedAt;
        try {
            for (User user : owned) {
                OwnedClient client = client(); clients.add(client); login(client, user);
            }
            // Interleaving keeps ordinary per-account browsing/polling below the global bound.
            // A separate short burst below 5 RPS is benign by scenario context, not discarded.
            for (int index = 0; index < 64; index++) {
                if (index == 32) login(clients.get(0), owned.get(0)); // Real second server-issued session.
                get(clients.get(0), browsing(index));
                get(clients.get(1), polling(index));
                if (index % 2 == 0) get(clients.get(2), boundedBurst(index / 2));
                if (index < 48) get(clients.get(3), ownedEndpointProbe(index));
            }
            for (int index = 32; index < 64; index++) get(clients.get(2), boundedBurst(index));
            finishedAt = Instant.now();
        } finally {
            for (OwnedClient client : clients) client.http().close();
        }
        assertThat(Duration.between(captureStartedAt, finishedAt)).isLessThanOrEqualTo(Duration.ofSeconds(60));
        assertThat(clientRequests).isEqualTo(250); // 240 GETs + 5 csrf reads + 5 real login POSTs.
        assertThat(loginCount).isEqualTo(5);
        List<SiemSecurityEvent> captured = new ArrayList<>();
        for (User user : owned) {
            int expected = user == owned.get(0) ? 66 : user == owned.get(3) ? 49 : 65;
            captured.addAll(awaitEvents(user.getId(), expected, finishedAt));
            assertThat(windows.countByAccountId(user.getId())).isZero();
            assertThat(users.findById(user.getId()).orElseThrow().getAuthVersion()).isZero();
        }
        assertThat(captured).hasSize(245);
        assertThat(jobs.count()).isEqualTo(modelJobsBefore);
        assertThat(mapper.writeValueAsString(captured)).doesNotContain(CANARY, PASSWORD, "access_token", "X-Forwarded-For");
        List<SiemSecurityEvent> http = captured.stream().filter(event -> "HTTP_REQUEST".equals(event.getEventType())).toList();
        assertThat(http).hasSize(240);
        assertThat(http.stream().filter(event -> owned.get(0).getId().equals(event.getActorUserId()))
                .map(SiemSecurityEvent::getSessionPseudonym).distinct()).hasSize(2);
        for (int index = 0; index < 3; index++) {
            String actor = owned.get(index).getId();
            assertThat(http.stream().filter(event -> actor.equals(event.getActorUserId()))
                    .map(SiemSecurityEvent::getHttpStatus).collect(Collectors.toSet())).contains(403, 404);
        }
        assertThat(http.stream().filter(event -> owned.get(3).getId().equals(event.getActorUserId()))
                .map(SiemSecurityEvent::getHttpStatus).collect(Collectors.toSet())).contains(200, 403, 404);
        ControlledTraceCaptureArtifacts.write(output, mapper, captured, accountAliases, scenarios,
                captureStartedAt, finishedAt, new ControlledTraceCaptureArtifacts.CaptureCounts(
                        240, loginCount, clientRequests, clientHttpStatuses, minimumSpacingNanos), forbidden);
        try (var artifacts = Files.list(output)) {
            assertThat(artifacts.map(path -> path.getFileName().toString()).toList())
                    .containsExactlyInAnyOrder(ControlledTraceCaptureArtifacts.EVENTS_FILE,
                            ControlledTraceCaptureArtifacts.SCENARIOS_FILE, ControlledTraceCaptureArtifacts.EVIDENCE_FILE);
        }
    }

    private RequestPlan browsing(int index) {
        if (index == 31 || index == 63) return new RequestPlan("/api/admin/users", 403);
        return switch (index % 8) {
            case 0 -> new RequestPlan("/api/products", 200);
            case 1 -> new RequestPlan("/api/profile", 200);
            case 2 -> new RequestPlan("/api/orders/me", 200);
            case 3 -> new RequestPlan("/api/promo-hunt/campaigns", 200);
            case 4 -> new RequestPlan("/api/sync/me/cart", 200);
            case 5 -> new RequestPlan("/api/products/query?q=" + CANARY, 200);
            case 6 -> new RequestPlan("/api/products/owned-missing-product", 404);
            default -> new RequestPlan("/api/profile/owned-stale-bookmark", 404);
        };
    }

    private RequestPlan polling(int index) {
        if (index == 31) return new RequestPlan("/api/admin/users", 403);
        if (index == 63) return new RequestPlan("/api/profile/owned-stale-bookmark", 404);
        return index % 2 == 0 ? new RequestPlan("/api/support/me", 204) : new RequestPlan("/api/sync/me/wishlist", 200);
    }

    private RequestPlan boundedBurst(int index) {
        if (index == 15) return new RequestPlan("/api/admin/users", 403);
        if (index == 47) return new RequestPlan("/api/products/owned-missing-product", 404);
        return switch (index % 4) {
            case 0 -> new RequestPlan("/api/products", 200);
            case 1 -> new RequestPlan("/api/profile", 200);
            case 2 -> new RequestPlan("/api/sync/me/cart", 200);
            default -> new RequestPlan("/api/orders/me", 200);
        };
    }

    private RequestPlan ownedEndpointProbe(int index) {
        if (index % 12 == 0) return new RequestPlan("/api/profile", 200);
        if (index % 8 == 7) return new RequestPlan("/api/admin/users", 403);
        String suffix = "/owned-controlled-probe-" + index;
        return switch (index % 4) {
            case 0 -> new RequestPlan("/api/profile" + suffix, 404);
            case 1 -> new RequestPlan("/api/support/me" + suffix, 404);
            case 2 -> new RequestPlan("/api/orders" + suffix + "/details", 404);
            default -> new RequestPlan("/api" + suffix, 404);
        };
    }

    private OwnedClient client() {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return new OwnedClient(HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build(), cookies);
    }

    private void login(OwnedClient client, User user) throws Exception {
        HttpResponse<String> csrfResponse = send(client, request("/api/auth/csrf").GET().build());
        assertThat(csrfResponse.statusCode()).isEqualTo(200);
        String csrf = mapper.readTree(csrfResponse.body()).path("token").asText();
        assertThat(csrf).isNotBlank(); forbidden.add(csrf);
        HttpResponse<String> response = send(client, request("/api/auth/login").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        Map.of("username", user.getUsername(), "password", PASSWORD)))).build());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).has("access_token")).isFalse();
        for (var cookie : client.cookies().getCookieStore().getCookies()) forbidden.add(cookie.getValue());
        loginCount++;
    }

    private void get(OwnedClient client, RequestPlan plan) throws Exception {
        String separator = plan.path().contains("?") ? "&" : "?";
        HttpResponse<String> response = send(client, request(plan.path() + separator + "private=" + CANARY)
                .header("X-Actor-User-Id", "forged-private-actor-" + CANARY)
                .header("X-Forwarded-For", "198.51.100.123").GET().build());
        assertThat(response.statusCode()).isEqualTo(plan.expectedStatus());
        clientHttpStatuses.merge(response.statusCode(), 1L, Long::sum);
    }

    private HttpResponse<String> send(OwnedClient client, HttpRequest request) throws Exception {
        if (lastSendNanos != 0) {
            long waitNanos = SEND_SPACING_NANOS - (System.nanoTime() - lastSendNanos);
            if (waitNanos > 0) TimeUnit.NANOSECONDS.sleep(waitNanos);
        }
        assertThat(Duration.between(captureStartedAt, Instant.now())).isLessThan(Duration.ofSeconds(60));
        long now = System.nanoTime();
        if (lastSendNanos != 0) minimumSpacingNanos = Math.min(minimumSpacingNanos, now - lastSendNanos);
        lastSendNanos = now; clientRequests++;
        return client.http().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "Mozilla/5.0 Firefox/128.0 " + CANARY);
    }

    private User customer() {
        String id = "controlled-private-" + opaqueId();
        User user = new User(); user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(PASSWORD));
        user.setRole("CUSTOMER"); user.setHoTen("Owned isolated capture fixture"); user.setStatus("Hoat dong");
        user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }

    private List<SiemSecurityEvent> awaitEvents(String actor, int expected, Instant finishedAt) throws InterruptedException {
        List<SiemSecurityEvent> found = List.of();
        for (int attempt = 0; attempt < 100; attempt++) {
            found = events.findAccountEvidence(actor, LocalDateTime.ofInstant(captureStartedAt, ZoneOffset.UTC),
                    LocalDateTime.ofInstant(finishedAt.plusSeconds(1), ZoneOffset.UTC), PageRequest.of(0, 500)).getContent();
            if (found.size() >= expected) break;
            Thread.sleep(20);
        }
        assertThat(found).hasSize(expected);
        return found;
    }

    private static ControlledTraceCaptureArtifacts.Scenario scenario(String alias, String family, String label) {
        return new ControlledTraceCaptureArtifacts.Scenario(alias, "scenario-" + opaqueId(), family, label);
    }

    private static String opaqueId() { return UUID.randomUUID().toString().replace("-", ""); }

    private static Path projectRoot() {
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        return Files.isRegularFile(cwd.resolve("backend/pom.xml")) ? cwd : cwd.getParent();
    }

    private record OwnedClient(HttpClient http, CookieManager cookies) {}
    private record RequestPlan(String path, int expectedStatus) {}
}
