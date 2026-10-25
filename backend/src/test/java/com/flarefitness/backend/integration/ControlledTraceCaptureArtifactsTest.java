package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ControlledTraceCaptureArtifactsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-10-02T03:00:00Z");
    private static final Instant FINISH = START.plusSeconds(2);
    private static final String SOURCE_ACCOUNT = "owned-source-account-private";
    private static final String ALIAS = "account-" + "a".repeat(32);
    private static final String SCENARIO_ID = "scenario-" + "b".repeat(32);
    private static final String SESSION = "c".repeat(64);
    private static final String PRIVATE_TRACE = "private-token@example.invalid";
    private static final long SPACING = Duration.ofMillis(200).toNanos();
    private static final Set<String> COMMON_FIELDS = Set.of("account_alias", "event_sequence", "event_timestamp",
            "event_type", "action", "outcome", "source_ip", "user_agent_family", "route_group");
    private static final List<ControlledTraceCaptureArtifacts.Scenario> SCENARIOS = List.of(
            new ControlledTraceCaptureArtifacts.Scenario(ALIAS, SCENARIO_ID, "OWNED_ENDPOINT_SCAN", "OWNED_ENDPOINT_SCAN"));
    private static final ControlledTraceCaptureArtifacts.CaptureCounts COUNTS =
            new ControlledTraceCaptureArtifacts.CaptureCounts(2, 1, 3, Map.of(200, 1L, 403, 1L), SPACING);

    @TempDir Path temporary;
    private int directorySequence;

    @Test void exportsOnlyAllowlistedActualFieldsWithPrivateModesUtcCountsAndIndependentHashes() throws Exception {
        Path output = freshOutput();
        var login = login();
        var success = http(200, START.plusSeconds(1));
        var denied = http(403, START.plusMillis(1200));
        write(output, List.of(denied, success, login), COUNTS, Set.of(PRIVATE_TRACE, "private-password-sentinel"));

        String eventText = Files.readString(output.resolve(ControlledTraceCaptureArtifacts.EVENTS_FILE));
        List<JsonNode> events = eventText.lines().map(line -> {
            try { return JSON.readTree(line); }
            catch (Exception failure) { throw new AssertionError(failure); }
        }).toList();
        assertThat(events).hasSize(3);
        assertThat(fields(events.get(0))).isEqualTo(COMMON_FIELDS);
        Set<String> httpFields = new HashSet<>(COMMON_FIELDS);
        httpFields.addAll(Set.of("http_method", "http_status", "telemetry_contract_version", "endpoint_category",
                "session_pseudonym", "session_issued_at"));
        assertThat(fields(events.get(1))).isEqualTo(httpFields);
        assertThat(fields(events.get(2))).isEqualTo(httpFields);
        assertThat(events.get(0).path("event_type").asText()).isEqualTo("AUTH");
        assertThat(events.get(0).path("event_timestamp").asText()).isEqualTo(START.plusMillis(200).toString());
        assertThat(events.get(1).path("event_timestamp").asText()).isEqualTo(START.plusSeconds(1).toString());
        assertThat(events.get(1).path("session_issued_at").asText()).isEqualTo(START.toString());
        assertThat(events.get(1).path("session_pseudonym").asText()).isEqualTo(SESSION);
        assertThat(events.get(2).path("outcome").asText()).isEqualTo("FAILURE");
        for (int index = 0; index < events.size(); index++) {
            assertThat(events.get(index).path("event_sequence").asInt()).isEqualTo(index);
            assertThat(events.get(index).path("account_alias").asText()).isEqualTo(ALIAS);
        }

        String scenarioText = Files.readString(output.resolve(ControlledTraceCaptureArtifacts.SCENARIOS_FILE));
        var scenarios = JSON.readTree(scenarioText);
        assertThat(scenarios.path("labels_separate_from_events").asBoolean()).isTrue();
        var scenario = scenarios.path("scenarios").get(0);
        assertThat(scenario.path("scenario_id").asText()).isEqualTo(SCENARIO_ID);
        assertThat(scenario.path("expected_label").asText()).isEqualTo("OWNED_ENDPOINT_SCAN");
        assertThat(scenario.path("observed_event_count").asInt()).isEqualTo(3);
        assertThat(scenario.path("observed_session_count").asInt()).isEqualTo(1);
        assertThat(eventText).doesNotContain(SCENARIO_ID, "OWNED_ENDPOINT_SCAN", "expected_label", "demo_label");

        String evidenceText = Files.readString(output.resolve(ControlledTraceCaptureArtifacts.EVIDENCE_FILE));
        var evidence = JSON.readTree(evidenceText);
        assertThat(evidence.path("passed").asBoolean()).isTrue();
        assertThat(evidence.path("capture_started_at").asText()).isEqualTo(START.toString());
        assertThat(evidence.path("capture_finished_at").asText()).isEqualTo(FINISH.toString());
        assertThat(evidence.path("capture_duration_millis").asLong()).isEqualTo(2000);
        assertThat(evidence.path("event_count").asInt()).isEqualTo(3);
        assertThat(evidence.path("http_request_count").asInt()).isEqualTo(2);
        assertThat(evidence.path("successful_login_count").asInt()).isEqualTo(1);
        assertThat(evidence.path("client_request_count").asInt()).isEqualTo(3);
        assertThat(evidence.path("minimum_send_spacing_nanos").asLong()).isEqualTo(SPACING);
        assertThat(evidence.path("maximum_client_requests_per_second").asInt()).isEqualTo(5);
        assertThat(evidence.path("event_type_counts")).isEqualTo(JSON.readTree("{\"AUTH\":1,\"HTTP_REQUEST\":2}"));
        assertThat(evidence.path("client_http_status_counts")).isEqualTo(JSON.readTree("{\"200\":1,\"403\":1}"));
        assertThat(evidence.path("server_http_status_counts")).isEqualTo(evidence.path("client_http_status_counts"));
        assertThat(evidence.path("trace_events_sha256").asText()).isEqualTo(digest(output.resolve(ControlledTraceCaptureArtifacts.EVENTS_FILE)));
        assertThat(evidence.path("scenarios_sha256").asText()).isEqualTo(digest(output.resolve(ControlledTraceCaptureArtifacts.SCENARIOS_FILE)));
        assertThat(evidence.path("timestamps_rewritten").asBoolean()).isFalse();
        assertThat(evidence.path("elapsed_window_closure_proven").asBoolean()).isFalse();
        assertThat(evidence.path("window_closure").asText()).isEqualTo("NOT_OBSERVED_NOT_FORCED");
        assertThat(eventText + scenarioText + evidenceText).doesNotContain(SOURCE_ACCOUNT, PRIVATE_TRACE,
                "source-event-login", "source-event-200", "source-event-403", "trace_id", "actor_user_id",
                "target_user_id", "createdAt", "/api/", "access_token", "Bearer ");
        assertThat(Files.getPosixFilePermissions(output)).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        assertThat(Files.getPosixFilePermissions(output.getParent())).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        try (var paths = Files.list(output)) {
            var files = paths.toList();
            assertThat(files.stream().map(path -> path.getFileName().toString())).containsExactlyInAnyOrder(
                    ControlledTraceCaptureArtifacts.EVENTS_FILE, ControlledTraceCaptureArtifacts.SCENARIOS_FILE,
                    ControlledTraceCaptureArtifacts.EVIDENCE_FILE);
            for (Path file : files) {
                assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
            }
        }
    }

    @Test void refusesMissingUnverifiedOrFutureSessionTelemetryBeforeWriting() throws Exception {
        List<Consumer<SiemSecurityEvent>> invalid = List.of(event -> event.setSessionPseudonym(null),
                event -> event.setSessionPseudonym("Bearer private-token"), event -> event.setSessionIssuedAt(null),
                event -> event.setSessionIssuedAt(FINISH.atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setTelemetryContractVersion(2));
        for (var mutation : invalid) assertInvalidHttp(mutation);
    }

    @Test void refusesRawCategoriesAgentsRoutesOrNonLoopbackSourcesBeforeWriting() throws Exception {
        List<Consumer<SiemSecurityEvent>> invalid = List.of(event -> event.setEndpointCategory("/api/profile/private"),
                event -> event.setUserAgentFamily("Mozilla/5.0 private-agent"),
                event -> event.setSourceIp("203.0.113.9"), event -> event.setRouteGroup("/api/products/private"));
        for (var mutation : invalid) assertInvalidHttp(mutation);
    }

    @Test void neverInventsAuthSessionsOrHttpFields() throws Exception {
        List<Consumer<SiemSecurityEvent>> invalid = List.of(event -> event.setSessionPseudonym(SESSION),
                event -> event.setSessionIssuedAt(START.atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setHttpMethod("POST"), event -> event.setHttpStatus(200));
        for (var mutation : invalid) {
            var auth = login(); mutation.accept(auth);
            assertRejected(freshOutput(), List.of(auth, http(200, START.plusSeconds(1)), http(403, START.plusMillis(1200))),
                    COUNTS, Set.of(PRIVATE_TRACE));
        }
    }

    @Test void refusesEventOrClientStatusCountMismatchAndDuplicateSourceEvents() throws Exception {
        for (var counts : List.of(new ControlledTraceCaptureArtifacts.CaptureCounts(3, 1, 4, Map.of(200, 1L, 403, 1L), SPACING),
                new ControlledTraceCaptureArtifacts.CaptureCounts(2, 2, 4, Map.of(200, 1L, 403, 1L), SPACING),
                new ControlledTraceCaptureArtifacts.CaptureCounts(2, 1, 3, Map.of(200, 2L), SPACING))) {
            assertRejected(freshOutput(), events(), counts, Set.of(PRIVATE_TRACE));
        }
        var duplicate = events(); duplicate.get(2).setId(duplicate.get(1).getId());
        assertRejected(freshOutput(), duplicate, COUNTS, Set.of(PRIVATE_TRACE));
    }

    @Test void refusesPrivacySentinelInAnyExportedContentAndMissingSentinel() throws Exception {
        for (String privateValue : List.of(SESSION, SCENARIO_ID, "NOT_RUN", " ")) {
            assertRejected(freshOutput(), events(), COUNTS, Set.of(privateValue));
        }
    }

    @Test void refusesNonOwnedOrLabelledEventsAndTimestampsOutsideActualUtcCapture() throws Exception {
        for (var mutation : List.<Consumer<SiemSecurityEvent>>of(event -> event.setActorUserId("unowned-account"),
                event -> event.setTargetUserId("other-account"), event -> event.setDemoLabel("NORMAL"),
                event -> event.setEventTimestamp(START.minusSeconds(1).atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setEventTimestamp(FINISH.plusSeconds(1).atOffset(ZoneOffset.UTC).toLocalDateTime()))) {
            assertInvalidHttp(mutation);
        }
    }

    @Test void refusesWorkloadOutsideTimeRequestOrRateBounds() throws Exception {
        Path tooLong = freshOutput();
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.write(tooLong, JSON, events(), Map.of(SOURCE_ACCOUNT, ALIAS),
                SCENARIOS, START, START.plusSeconds(61), COUNTS, Set.of(PRIVATE_TRACE))).isInstanceOf(IllegalArgumentException.class);
        assertEmpty(tooLong);
        Path backwards = freshOutput();
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.write(backwards, JSON, events(), Map.of(SOURCE_ACCOUNT, ALIAS),
                SCENARIOS, START, START.minusSeconds(1), COUNTS, Set.of(PRIVATE_TRACE))).isInstanceOf(IllegalArgumentException.class);
        assertEmpty(backwards);
        assertRejected(freshOutput(), events(), new ControlledTraceCaptureArtifacts.CaptureCounts(2, 1, 301,
                COUNTS.clientHttpStatusCounts(), SPACING), Set.of(PRIVATE_TRACE));
        assertRejected(freshOutput(), events(), new ControlledTraceCaptureArtifacts.CaptureCounts(2, 1, 3,
                COUNTS.clientHttpStatusCounts(), SPACING - 1), Set.of(PRIVATE_TRACE));
    }

    @Test void rejectsNonfreshOutsideNestedOrMalformedOutputDirectories() throws Exception {
        Path project = project("paths");
        Path runtime = Files.createDirectory(project.resolve("observability/runtime"));
        Path existing = Files.createDirectory(runtime.resolve("existing"));
        Path file = Files.createFile(runtime.resolve("existing-file"));
        Path linked = Files.createSymbolicLink(runtime.resolve("linked"), existing);
        for (Path path : List.of(existing, file, linked, temporary.resolve("outside"), runtime.resolve("nested/child"),
                runtime.resolve(".hidden"))) {
            assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(project, path.toString()))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(project, " "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void rejectsSymlinkedProjectObservabilityOrRuntimeDirectories() throws Exception {
        Path project = project("real-project");
        Path linkedProject = Files.createSymbolicLink(temporary.resolve("project-link"), project);
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(linkedProject,
                linkedProject.resolve("observability/runtime/capture").toString())).isInstanceOf(IllegalArgumentException.class);

        Path linkedObservability = project("observability-project");
        Files.delete(linkedObservability.resolve("observability"));
        Files.createSymbolicLink(linkedObservability.resolve("observability"), project.resolve("observability"));
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(linkedObservability,
                linkedObservability.resolve("observability/runtime/capture").toString())).isInstanceOf(IllegalArgumentException.class);

        Path linkedRuntime = project("runtime-project");
        Files.createSymbolicLink(linkedRuntime.resolve("observability/runtime"), Files.createDirectory(temporary.resolve("runtime-target")));
        assertThatThrownBy(() -> ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(linkedRuntime,
                linkedRuntime.resolve("observability/runtime/capture").toString())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void refusesNonprivateAndSymlinkedWriterDirectories() throws Exception {
        Path nonprivate = freshOutput();
        Files.setPosixFilePermissions(nonprivate, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertRejected(nonprivate, events(), COUNTS, Set.of(PRIVATE_TRACE));
        Path target = freshOutput();
        Path link = Files.createSymbolicLink(temporary.resolve("writer-link"), target);
        assertThatThrownBy(() -> write(link, events(), COUNTS, Set.of(PRIVATE_TRACE))).isInstanceOf(IllegalArgumentException.class);
        assertEmpty(target);
    }

    private Path project(String name) throws Exception {
        Path root = Files.createDirectory(temporary.resolve(name)).toRealPath();
        Files.createDirectory(root.resolve("backend")); Files.createFile(root.resolve("backend/pom.xml"));
        Files.createDirectory(root.resolve("observability"));
        return root;
    }

    private Path freshOutput() throws Exception {
        Path root = project("capture-project-" + directorySequence++);
        return ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(root,
                root.resolve("observability/runtime/capture").toString());
    }

    private void assertInvalidHttp(Consumer<SiemSecurityEvent> mutation) throws Exception {
        var captured = events(); mutation.accept(captured.get(1));
        assertRejected(freshOutput(), captured, COUNTS, Set.of(PRIVATE_TRACE));
    }

    private void assertRejected(Path output, List<SiemSecurityEvent> captured,
                                ControlledTraceCaptureArtifacts.CaptureCounts counts, Set<String> privateValues) throws Exception {
        assertThatThrownBy(() -> write(output, captured, counts, privateValues)).isInstanceOf(IllegalArgumentException.class);
        assertEmpty(output);
    }

    private static void assertEmpty(Path output) throws Exception {
        try (var paths = Files.list(output)) { assertThat(paths).isEmpty(); }
    }

    private static void write(Path output, List<SiemSecurityEvent> events,
                              ControlledTraceCaptureArtifacts.CaptureCounts counts, Set<String> privateValues) throws Exception {
        ControlledTraceCaptureArtifacts.write(output, JSON, events, Map.of(SOURCE_ACCOUNT, ALIAS), SCENARIOS,
                START, FINISH, counts, privateValues);
    }

    private static Set<String> fields(JsonNode node) {
        Set<String> fields = new HashSet<>(); node.fieldNames().forEachRemaining(fields::add); return fields;
    }

    private static String digest(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static List<SiemSecurityEvent> events() {
        return List.of(login(), http(200, START.plusSeconds(1)), http(403, START.plusMillis(1200)));
    }

    private static SiemSecurityEvent base(String id, Instant timestamp) {
        var event = new SiemSecurityEvent(); event.setId(id); event.setActorUserId(SOURCE_ACCOUNT);
        event.setEventTimestamp(timestamp.atOffset(ZoneOffset.UTC).toLocalDateTime());
        event.setSourceIp("127.0.0.1"); event.setUserAgentFamily("OTHER"); event.setTraceId(PRIVATE_TRACE);
        event.setCreatedAt(START.minusSeconds(10).atOffset(ZoneOffset.UTC).toLocalDateTime());
        return event;
    }

    private static SiemSecurityEvent login() {
        var event = base("source-event-login", START.plusMillis(200)); event.setTargetUserId(SOURCE_ACCOUNT);
        event.setEventType("AUTH"); event.setAction("LOGIN"); event.setOutcome("SUCCESS"); event.setRouteGroup("auth");
        return event;
    }

    private static SiemSecurityEvent http(int status, Instant timestamp) {
        var event = base("source-event-" + status, timestamp);
        event.setEventType("HTTP_REQUEST"); event.setAction("API_REQUEST"); event.setOutcome(status >= 400 ? "FAILURE" : "SUCCESS");
        event.setRouteGroup("products"); event.setHttpMethod("GET"); event.setHttpStatus(status);
        event.setTelemetryContractVersion(UebaSessionTelemetry.CONTRACT_VERSION); event.setEndpointCategory("PRODUCT_LIST");
        event.setSessionPseudonym(SESSION); event.setSessionIssuedAt(START.atOffset(ZoneOffset.UTC).toLocalDateTime());
        return event;
    }
}
