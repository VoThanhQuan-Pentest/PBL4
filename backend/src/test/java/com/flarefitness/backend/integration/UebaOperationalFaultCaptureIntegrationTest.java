package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.controller.OwnedLabControlledFaultController;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.service.siem.AccountBehaviorAggregationWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorScoringWorker;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import com.flarefitness.backend.service.siem.SiemIncidentService;
import com.flarefitness.backend.service.siem.UebaScorePolicy;
import com.flarefitness.backend.service.siem.UebaTestPolicies;
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
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Opt-in real HTTP source capture, never an accuracy, attack or elapsed-window qualification.
 * UEBA_OPERATIONAL_CAPTURE_ENABLED=true and UEBA_OPERATIONAL_CAPTURE_OUTPUT_DIR must name a fresh
 * absolute direct child of project observability/runtime. Runs only loopback + inherited ephemeral
 * Testcontainers MySQL/Redis; real login/CSRF/JWT/Redis allowlist and rate limiter remain enabled.
 */
@EnabledIfEnvironmentVariable(named = "UEBA_OPERATIONAL_CAPTURE_ENABLED", matches = "true")
@Import(OwnedLabControlledFaultController.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1",
        "siem.enabled=false", "siem.ueba.enabled=true", "siem.ueba.candidate-acceptance.enabled=true",
        "siem.ueba.initial-delay-ms=3600000", "siem.prevention.enabled=false",
        "siem.prevention.demo-enabled=false", "siem.security-events.enabled=true",
        "app.security.trusted-proxy-cidrs=", "spring.mail.host=127.0.0.1", "logging.level.AUDIT=OFF"
})
class UebaOperationalFaultCaptureIntegrationTest extends ContainerizedIntegrationTest {
    private static final String PASSWORD = "OperationalCapture#LocalOnly1";
    private static final String CANARY = "private-operational-query-agent-must-not-persist";
    private static final String CANDIDATE_VERSION = "local-candidate-v4-demo";
    private static final String RATE_LIMIT_PREFIX = "test:ueba-operational-capture:" + UUID.randomUUID() + ":";
    private static final long SEND_SPACING_NANOS = Duration.ofMillis(210).toNanos();
    @LocalServerPort private int port;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private ObjectMapper mapper;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private SiemIncidentService incidentService;
    @Autowired private AccountBehaviorAggregationWorker aggregation;
    @Autowired private AccountBehaviorScoringWorker scoring;
    @Value("${app.security.auth-cookie-name}") private String authCookieName;
    // Only the unrelated raw-ID disk sink is replaced, never HTTP auth, telemetry or its DB writer.
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    // Acceptance harness controls only the returned score; HTTP capture, aggregation, persistence and incident mapping are real.
    @MockitoBean private SiemUebaGateway candidateWorker;
    private final List<ControlledOperationalCaptureArtifacts.ClientObservation> ledger = new ArrayList<>();
    private final Set<String> forbidden = new HashSet<>(Set.of(PASSWORD, CANARY));
    private long lastSendNanos;
    private long minimumSpacingNanos = Long.MAX_VALUE;
    private Instant captureStartedAt;

    @DynamicPropertySource
    static void isolatedRateLimitNamespace(DynamicPropertyRegistry registry) {
        registry.add("app.security.login-attempt-prefix", () -> RATE_LIMIT_PREFIX);
    }

    @Test
    void capturesActualControlled503AndAmbiguousResourceReadsWithAllNormalCasesRetained() throws Exception {
        Path output = ControlledOperationalCaptureArtifacts.createFreshPrivateDirectory(projectRoot(),
                System.getenv("UEBA_OPERATIONAL_CAPTURE_OUTPUT_DIR"));
        User operational = customer();
        User resource = customer();
        Map<String, String> aliases = new LinkedHashMap<>();
        aliases.put(operational.getId(), "account-" + opaqueId());
        aliases.put(resource.getId(), "account-" + opaqueId());
        List<ControlledOperationalCaptureArtifacts.Scenario> scenarios = List.of(
                scenario(aliases.get(operational.getId()), "OPERATIONAL_FAULT", "CONTROLLED_OPERATIONAL_ANOMALY"),
                scenario(aliases.get(resource.getId()), "OWNED_RESOURCE_PROBE", "OBSERVATIONAL_AMBIGUOUS"));
        long modelJobsBefore = jobs.count();
        captureStartedAt = Instant.now();
        Instant finishedAt;
        try (OwnedClient faultClient = client(aliases.get(operational.getId()));
             OwnedClient resourceClient = client(aliases.get(resource.getId()))) {
            login(faultClient, operational); login(resourceClient, resource);
            for (int index = 0; index < 5; index++) get(faultClient,
                    index % 2 == 0 ? "/api/products" : "/api/profile", "NORMAL_READ", 200);
            for (int index = 0; index < 10; index++) get(faultClient,
                    "/api/owned-lab/controlled-faults", "CONTROLLED_FAULT", 503);
            get(faultClient, "/api/profile", "AFTER_FAULT_NORMAL_READ", 200);
            // These ordinary bounded reads are observationally benign-equivalent. They do not
            // exhaust resources, demonstrate disruption/DoS, or confirm malicious intent.
            for (int index = 0; index < 20; index++) get(resourceClient, switch (index % 4) {
                case 0 -> "/api/products";
                case 1 -> "/api/profile";
                case 2 -> "/api/orders/me";
                default -> "/api/sync/me/cart";
            }, "RESOURCE_PROBE", 200);
            finishedAt = Instant.now();
        }
        assertThat(Duration.between(captureStartedAt, finishedAt)).isLessThanOrEqualTo(Duration.ofSeconds(60));
        assertThat(ledger).hasSize(40); // 36 GETs + two real CSRF reads and two real login POSTs.
        List<SiemSecurityEvent> captured = new ArrayList<>(awaitEvents(operational.getId(), 17, finishedAt));
        captured.addAll(awaitEvents(resource.getId(), 21, finishedAt));
        assertThat(captured).hasSize(38);
        List<SiemSecurityEvent> http = captured.stream().filter(event -> "HTTP_REQUEST".equals(event.getEventType())).toList();
        assertThat(http).hasSize(36);
        assertThat(http.stream().filter(event -> Integer.valueOf(503).equals(event.getHttpStatus()))).hasSize(10)
                .allSatisfy(event -> {
                    assertThat(event.getActorUserId()).isEqualTo(operational.getId());
                    assertThat(event.getRouteGroup()).isEqualTo("other_api");
                    assertThat(event.getEndpointCategory()).isEqualTo("OTHER_MATCHED");
                    assertThat(event.getOutcome()).isEqualTo("FAILURE");
                    assertThat(event.getTelemetryContractVersion()).isEqualTo(3);
                    assertThat(event.getSessionPseudonym()).matches("[a-f0-9]{64}");
                    assertThat(event.getSessionIssuedAt()).isNotNull();
                });
        assertThat(http.stream().filter(event -> Integer.valueOf(200).equals(event.getHttpStatus()))).hasSize(26);
        for (User user : List.of(operational, resource)) {
            assertThat(windows.countByAccountId(user.getId())).isZero();
            assertThat(users.findById(user.getId()).orElseThrow().getAuthVersion()).isZero();
            assertThat(http.stream().filter(event -> user.getId().equals(event.getActorUserId()))
                    .map(SiemSecurityEvent::getSessionPseudonym).distinct()).hasSize(1);
        }
        assertThat(jobs.count()).isEqualTo(modelJobsBefore);
        assertThat(mapper.writeValueAsString(captured)).doesNotContain(CANARY, PASSWORD, "access_token", "X-Forwarded-For");

        // Exercise the real HTTP -> MySQL -> schema-4 aggregation -> candidate scoring -> incident path.
        // Only the worker score response is deterministic here; this is not model-quality evidence.
        LocalDateTime latest = captured.stream().map(SiemSecurityEvent::getEventTimestamp)
                .max(LocalDateTime::compareTo).orElseThrow();
        LocalDateTime closedAt = windowStart(latest).plusMinutes(17);
        aggregation.aggregatePendingAt(closedAt);
        LocalDateTime from = windowStart(captured.stream().map(SiemSecurityEvent::getEventTimestamp)
                .min(LocalDateTime::compareTo).orElseThrow()).minusMinutes(15);
        LocalDateTime to = windowStart(latest).plusMinutes(30);
        List<String> selectedWindowIds = new ArrayList<>();
        for (User user : List.of(operational, resource)) {
            var accountWindows = windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(
                    user.getId(), from, to);
            assertThat(accountWindows).isNotEmpty().allSatisfy(window -> {
                assertThat(window.hasModelFeatures(4)).isTrue();
                assertThat(window.getScoreStatus().name()).isEqualTo("PENDING");
            });
            accountWindows.forEach(window -> selectedWindowIds.add(window.getId()));
        }
        var strictPolicy = UebaScorePolicy.fromWire(UebaTestPolicies.sessionEndpoint(mapper), 4);
        when(candidateWorker.scoreCandidate(eq(CANDIDATE_VERSION), anyList(), eq(4), anyList()))
                .thenAnswer(call -> {
                    List<List<Double>> vectors = call.getArgument(1);
                    List<String> cohorts = call.getArgument(3);
                    List<SiemUebaGateway.Score> scores = new ArrayList<>();
                    for (int index = 0; index < vectors.size(); index++) {
                        List<Double> vector = vectors.get(index);
                        boolean operationalOnly = vector.get(2) >= 3 && vector.get(1) < 5
                                && vector.get(3) < 3 && vector.get(5) < 1;
                        double percentile = operationalOnly ? 100.0 : 0.0;
                        scores.add(new SiemUebaGateway.Score(operationalOnly ? 1.0 : 0.0, percentile,
                                strictPolicy.level(percentile, cohorts.get(index)), strictPolicy, cohorts.get(index)));
                    }
                    return new SiemUebaGateway.ScoreBatch(true, CANDIDATE_VERSION, null, scores, 4,
                            strictPolicy, "d".repeat(64));
                });
        scoring.scorePendingCandidateAt(closedAt, CANDIDATE_VERSION, selectedWindowIds);

        var operationalWindows = windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(
                operational.getId(), from, to);
        assertThat(operationalWindows).allSatisfy(window -> {
            assertThat(window.getModelVersion()).isEqualTo(CANDIDATE_VERSION);
            assertThat(window.getScoredFeatureSchemaVersion()).isEqualTo(4);
        });
        assertThat(windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(
                resource.getId(), from, to)).allSatisfy(window ->
                assertThat(window.getModelVersion()).isEqualTo(CANDIDATE_VERSION));
        var operationalIncidents = incidents.findAll().stream()
                .filter(incident -> operational.getId().equals(incident.getTargetUserId())
                        && incident.getOrigin() == IncidentOrigin.UEBA).toList();
        assertThat(operationalIncidents).isNotEmpty();
        assertThat(operationalIncidents).allSatisfy(incident -> {
            assertThat(incident.getNature()).isIn(IncidentNature.OPERATIONAL_ANOMALY,
                    IncidentNature.MIXED_ANOMALY);
            assertThat(incidentService.getIncident(incident.getId()).incident().nature())
                    .isEqualTo(incident.getNature());
        });
        assertThat(incidents.countByTargetUserIdAndOrigin(resource.getId(), IncidentOrigin.UEBA)).isZero();
        assertThat(jobs.count()).isEqualTo(modelJobsBefore);
        ControlledOperationalCaptureArtifacts.write(output, mapper, captured, aliases, scenarios, ledger,
                captureStartedAt, finishedAt, minimumSpacingNanos, forbidden);
        try (var artifacts = Files.list(output)) {
            assertThat(artifacts.map(path -> path.getFileName().toString()).toList()).containsExactlyInAnyOrder(
                    ControlledOperationalCaptureArtifacts.EVENTS_FILE, ControlledOperationalCaptureArtifacts.SCENARIOS_FILE,
                    ControlledOperationalCaptureArtifacts.CLIENT_LEDGER_FILE, ControlledOperationalCaptureArtifacts.EVIDENCE_FILE);
        }
    }

    private OwnedClient client(String alias) {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return new OwnedClient(alias, HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build(), cookies);
    }

    private void login(OwnedClient client, User user) throws Exception {
        HttpResponse<String> csrfResponse = send(client, request("/api/auth/csrf").GET().build(), "CSRF_READ", 200);
        String csrf = mapper.readTree(csrfResponse.body()).path("token").asText();
        assertThat(csrf).isNotBlank(); forbidden.add(csrf);
        HttpResponse<String> response = send(client, request("/api/auth/login").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        Map.of("username", user.getUsername(), "password", PASSWORD)))).build(), "LOGIN", 200);
        assertThat(mapper.readTree(response.body()).has("access_token")).isFalse();
        assertThat(client.cookies().getCookieStore().getCookies()).anyMatch(cookie -> authCookieName.equals(cookie.getName()));
        for (var cookie : client.cookies().getCookieStore().getCookies()) forbidden.add(cookie.getValue());
    }

    private void get(OwnedClient client, String path, String kind, int expectedStatus) throws Exception {
        HttpResponse<String> response = send(client, request(path + "?private=" + CANARY)
                .header("X-Actor-User-Id", "forged-private-actor-" + CANARY)
                .header("X-Forwarded-For", "198.51.100.123").GET().build(), kind, expectedStatus);
        if (expectedStatus == 503) {
            assertThat(mapper.readTree(response.body()).path("code").asText()).isEqualTo("SIEM_UNAVAILABLE");
            assertThat(response.body()).doesNotContain("ServiceUnavailableException", "stackTrace", CANARY);
        }
    }

    private HttpResponse<String> send(OwnedClient client, HttpRequest request, String kind, int expected) throws Exception {
        if (lastSendNanos != 0) {
            long waitNanos = SEND_SPACING_NANOS - (System.nanoTime() - lastSendNanos);
            if (waitNanos > 0) TimeUnit.NANOSECONDS.sleep(waitNanos);
        }
        assertThat(Duration.between(captureStartedAt, Instant.now())).isLessThan(Duration.ofSeconds(60));
        long now = System.nanoTime();
        if (lastSendNanos != 0) minimumSpacingNanos = Math.min(minimumSpacingNanos, now - lastSendNanos);
        lastSendNanos = now;
        Instant sentAt = Instant.now();
        HttpResponse<String> response = client.http().send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(expected);
        ledger.add(new ControlledOperationalCaptureArtifacts.ClientObservation(client.alias(), sentAt, kind,
                request.method(), expected, response.statusCode()));
        return response;
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "Mozilla/5.0 Firefox/128.0 " + CANARY);
    }

    private User customer() {
        String id = "operational-private-" + opaqueId();
        forbidden.add(id);
        User user = new User(); user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(PASSWORD));
        user.setRole("CUSTOMER"); user.setHoTen("Owned isolated operational capture fixture"); user.setStatus("Hoat dong");
        user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }

    private List<SiemSecurityEvent> awaitEvents(String actor, int expected, Instant finishedAt) throws InterruptedException {
        List<SiemSecurityEvent> found = List.of();
        for (int attempt = 0; attempt < 100; attempt++) {
            found = events.findAccountEvidence(actor, LocalDateTime.ofInstant(captureStartedAt, ZoneOffset.UTC),
                    LocalDateTime.ofInstant(finishedAt.plusSeconds(1), ZoneOffset.UTC), PageRequest.of(0, 100)).getContent();
            if (found.size() >= expected) break;
            Thread.sleep(20);
        }
        assertThat(found).hasSize(expected);
        return found;
    }

    private static ControlledOperationalCaptureArtifacts.Scenario scenario(String alias, String family, String label) {
        return new ControlledOperationalCaptureArtifacts.Scenario(alias, "scenario-" + opaqueId(), family, label);
    }
    private static String opaqueId() { return UUID.randomUUID().toString().replace("-", ""); }
    private static LocalDateTime windowStart(LocalDateTime timestamp) {
        return timestamp.withMinute(timestamp.getMinute() / 15 * 15).withSecond(0).withNano(0);
    }
    private static Path projectRoot() {
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        return Files.isRegularFile(cwd.resolve("backend/pom.xml")) ? cwd : cwd.getParent();
    }
    private record OwnedClient(String alias, HttpClient http, CookieManager cookies) implements AutoCloseable {
        @Override public void close() { http.close(); }
    }
}
