package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.siem.AccountBaselinePolicy;
import com.flarefitness.backend.service.siem.AccountBehaviorAggregationWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.AccountBehaviorScoringWorker;
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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Actual loopback HTTP -> authentication/filter -> MySQL -> production features.
 * The deterministic closure entry point is not an elapsed-time/shadow proof.
 * No model is trained or promoted; strict ML-only/UI acceptance is a separate gate. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "siem.security-events.enabled=true",
        "siem.security-events.export-initial-delay-ms=3600000",
        "siem.ueba.enabled=false",
        "siem.security-events.export-interval-ms=3600000",
        "app.security.trusted-proxy-cidrs="
})
class UebaLiveCaptureIntegrationTest extends ContainerizedIntegrationTest {
    private static final String PASSWORD = "LocalCapture#1";
    private static final String CANARY = "capture-query-body-agent-must-not-be-persisted";
    private static final ZoneId BEHAVIOR_ZONE = ZoneId.of("Asia/Ho_Chi_Minh");
    private static final String RATE_LIMIT_PREFIX = "test:ueba-live-capture:" + UUID.randomUUID() + ":";
    private static final Path EXPORT = Path.of(System.getProperty("java.io.tmpdir"),
            "flare-live-capture-" + UUID.randomUUID() + ".ndjson");
    @LocalServerPort private int port;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private ObjectMapper mapper;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private AccountBehaviorAggregationWorker aggregation;
    @Autowired private AccountBehaviorScoringWorker scoring;

    @DynamicPropertySource
    static void privateExportPath(DynamicPropertyRegistry registry) {
        registry.add("siem.security-events.output-file", EXPORT::toString);
        registry.add("app.security.login-attempt-prefix", () -> RATE_LIMIT_PREFIX);
    }

    @AfterAll
    void removeOwnedTemporaryExport() throws Exception {
        Files.deleteIfExists(EXPORT);
    }

    @Test
    void actualHttpCaptureUsesServerActorAndProducesIdempotentColdFeatures() throws Exception {
        User customer = customer();
        User decoy = customer();
        LocalDateTime from = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1);
        try (HttpClient client = client()) {
            login(client, customer);
            for (int index = 0; index < 12; index++) {
                String path = index % 2 == 0 ? "/api/profile" : "/api/products";
                assertThat(get(client, path + "?private=" + CANARY, decoy.getId()).statusCode()).isEqualTo(200);
            }
            assertThat(get(client, "/api/admin/users", decoy.getId()).statusCode()).isEqualTo(403);
            var missing = get(client, "/api/profile/missing-capture-path", decoy.getId());
            assertThat(missing.statusCode()).isEqualTo(404);
            assertThat(mapper.readTree(missing.body()).path("code").asText()).isEqualTo("RESOURCE_NOT_FOUND");
            assertThat(get(client, "/api/health", decoy.getId()).statusCode()).isEqualTo(200);
            assertThat(get(client, "/api/auth/me", decoy.getId()).statusCode()).isEqualTo(200);
        }
        List<SiemSecurityEvent> captured = awaitEvents(customer.getId(), from, 15);
        assertThat(captured).hasSize(15);
        assertThat(captured).allSatisfy(event -> {
            assertThat(event.getActorUserId()).isEqualTo(customer.getId());
            assertThat(event.getSourceIp()).isEqualTo("127.0.0.1");
            assertThat(event.getUserAgentFamily()).isEqualTo("FIREFOX");
            assertThat(event.getDemoLabel()).isNull();
        });
        var httpEvents = captured.stream().filter(event -> "HTTP_REQUEST".equals(event.getEventType())).toList();
        assertThat(httpEvents)
                .hasSize(14).allSatisfy(event -> assertThat(event.getHttpMethod()).isEqualTo("GET"));
        assertThat(httpEvents.stream().collect(Collectors.groupingBy(SiemSecurityEvent::getHttpStatus, Collectors.counting())))
                .containsExactlyInAnyOrderEntriesOf(Map.of(200, 12L, 403, 1L, 404, 1L));
        assertThat(httpEvents).allSatisfy(event -> {
            assertThat(event.getTelemetryContractVersion()).isEqualTo(3);
            assertThat(event.getSessionPseudonym()).matches("[a-f0-9]{64}");
            assertThat(event.getSessionIssuedAt()).isNotNull().isBeforeOrEqualTo(event.getEventTimestamp());
        });
        assertThat(httpEvents.stream().map(SiemSecurityEvent::getSessionPseudonym).distinct()).hasSize(1);
        assertThat(httpEvents.stream().collect(Collectors.groupingBy(SiemSecurityEvent::getEndpointCategory, Collectors.counting())))
                .containsExactlyInAnyOrderEntriesOf(Map.of("PROFILE_READ", 6L, "PRODUCT_LIST", 6L, "UNRESOLVED", 1L, "UNMATCHED", 1L));
        assertThat(captured.stream().filter(event -> "AUTH".equals(event.getEventType())).toList())
                .singleElement().satisfies(event -> {
                    assertThat(event.getAction()).isEqualTo("LOGIN");
                    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
                });
        assertThat(mapper.writeValueAsString(captured)).doesNotContain(CANARY, PASSWORD, "access_token", "X-Forwarded-For");
        assertThat(accountEvents(decoy.getId(), from)).isEmpty();

        var capturedIds = captured.stream().map(SiemSecurityEvent::getId).collect(Collectors.toSet());
        // Exercise the real serializer/file writer on exactly these persisted
        // rows; do not drain unrelated Testcontainers outbox fixtures from other classes.
        var persisted = new ArrayList<SiemSecurityEvent>();
        events.findAllById(capturedIds).forEach(persisted::add);
        assertThat(persisted).hasSize(captured.size()).allSatisfy(event -> assertThat(event.getExportedAt()).isNull());
        var exportRepository = mock(SiemSecurityEventRepository.class);
        when(exportRepository.findByExportedAtIsNullOrderByCreatedAtAsc(PageRequest.of(0, 200)))
                .thenReturn(persisted);
        var localExporter = new SecurityEventExportWorker(exportRepository, mapper, true,
                EXPORT.toString(), 64L * 1024 * 1024);
        localExporter.exportPending();
        verify(exportRepository, times(captured.size())).save(any(SiemSecurityEvent.class));
        var exportedIds = Files.readAllLines(EXPORT).stream().map(line -> {
            try { return mapper.readTree(line).path("event").path("id").asText(); }
            catch (Exception failure) { throw new AssertionError("Invalid exported event JSON", failure); }
        }).filter(capturedIds::contains).toList();
        assertThat(exportedIds).containsExactlyInAnyOrderElementsOf(captured.stream().map(SiemSecurityEvent::getId).toList());
        assertThat(Files.readString(EXPORT)).doesNotContain(CANARY, PASSWORD, "access_token");

        Map<LocalDateTime, List<SiemSecurityEvent>> partitions = captured.stream()
                .collect(Collectors.groupingBy(event -> start(event.getEventTimestamp())));
        LocalDateTime closedAt = partitions.keySet().stream().max(LocalDateTime::compareTo).orElseThrow().plusMinutes(17);
        // Exercise the real transaction/closure logic without rewriting source timestamps.
        aggregation.aggregatePendingAt(closedAt);
        aggregation.aggregatePendingAt(closedAt.plusSeconds(1));
        assertThat(windows.countByAccountId(customer.getId())).isEqualTo(partitions.size());
        double[] totals = new double[6];
        for (var partition : partitions.entrySet()) {
            var actual = windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(
                    customer.getId(), partition.getKey(), AccountBehaviorFeatures.SCHEMA_VERSION).orElseThrow();
            var baseline = AccountBaselinePolicy.summarize(List.of(), partition.getKey(), BEHAVIOR_ZONE);
            var expected = AccountBehaviorFeatures.fromEvents(partition.getValue(), baseline.features(), BEHAVIOR_ZONE);
            assertThat(actual.getEventCount()).isEqualTo(partition.getValue().size());
            assertThat(actual.featureVector()).isEqualTo(expected.values());
            assertThat(actual.modelFeatureVector(2)).isEqualTo(AccountBehaviorFeatures.withPersonalFeatures(expected, baseline).values());
            assertThat(actual.modelFeatureVector(4)).hasSize(37);
            assertThat(actual.modelFeatureVector(4).subList(0, 25)).isEqualTo(actual.modelFeatureVector(3));
            assertThat(actual.modelFeatureVector(4).get(25)).isEqualTo((double) partition.getValue().stream()
                    .filter(event -> "HTTP_REQUEST".equals(event.getEventType())).count());
            assertThat(actual.modelFeatureVector(2).subList(11, 13)).containsExactly(0.0, 0.0);
            for (int index = 0; index < totals.length; index++) totals[index] += actual.featureVector().get(index);
            assertThat(actual.isBaselineEstablished()).isFalse();
            assertThat(actual.getDemoLabel()).isEqualTo("REAL");
        }
        assertThat(totals).containsExactly(14.0, 2.0, 0.0, 0.0, 1.0, 0.0);
        assertThat(accountEvents(customer.getId(), from)).allSatisfy(event -> assertThat(event.getAggregatedAt()).isNotNull());
        scoring.scorePendingAt(closedAt);
        scoring.scorePendingAt(closedAt.plusSeconds(1));
        assertThat(incidents.countByTargetUserIdAndOrigin(customer.getId(), IncidentOrigin.UEBA)).isZero();
        assertThat(users.findById(customer.getId()).orElseThrow().getAuthVersion()).isZero();
    }

    @Test
    void anonymousHeadersCannotInventAnAccountEvent() throws Exception {
        User decoy = customer();
        LocalDateTime from = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1);
        try (HttpClient anonymous = client()) {
            assertThat(get(anonymous, "/api/products", decoy.getId()).statusCode()).isEqualTo(200);
            assertThat(get(anonymous, "/api/profile", decoy.getId()).statusCode()).isEqualTo(401);
        }
        assertThat(accountEvents(decoy.getId(), from)).isEmpty();
        assertThat(windows.countByAccountId(decoy.getId())).isZero();
    }

    private HttpClient client() {
        return HttpClient.newBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    private void login(HttpClient client, User customer) throws Exception {
        var csrfResponse = client.send(request("/api/auth/csrf").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(csrfResponse.statusCode()).isEqualTo(200);
        String csrf = mapper.readTree(csrfResponse.body()).path("token").asText();
        var response = client.send(request("/api/auth/login").header("Content-Type", "application/json")
                .header("X-XSRF-TOKEN", csrf).POST(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(Map.of("username", customer.getUsername(), "password", PASSWORD))))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(response.body()).has("access_token")).isFalse();
    }

    private HttpResponse<String> get(HttpClient client, String path, String forgedAccount) throws Exception {
        return client.send(request(path).header("X-Actor-User-Id", forgedAccount).header("X-User-Id", forgedAccount)
                .header("X-Forwarded-For", "198.51.100.22").GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "Mozilla/5.0 Firefox/128.0 " + CANARY);
    }

    private User customer() {
        String id = "live-capture-" + UUID.randomUUID().toString().substring(0, 12);
        User user = new User(); user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(PASSWORD));
        user.setRole("CUSTOMER"); user.setHoTen("Owned HTTP capture fixture"); user.setStatus("Hoat dong");
        user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }

    private List<SiemSecurityEvent> accountEvents(String account, LocalDateTime from) {
        return events.findAccountEvidence(account, from, LocalDateTime.now(ZoneOffset.UTC).plusMinutes(1),
                PageRequest.of(0, 100)).getContent();
    }

    private List<SiemSecurityEvent> awaitEvents(String account, LocalDateTime from, int expected) throws InterruptedException {
        for (int attempt = 0; attempt < 100; attempt++) {
            List<SiemSecurityEvent> found = accountEvents(account, from);
            if (found.size() >= expected) return found;
            Thread.sleep(20);
        }
        return accountEvents(account, from);
    }

    private static LocalDateTime start(LocalDateTime timestamp) {
        return timestamp.withMinute(timestamp.getMinute() / 15 * 15).withSecond(0).withNano(0);
    }
}
