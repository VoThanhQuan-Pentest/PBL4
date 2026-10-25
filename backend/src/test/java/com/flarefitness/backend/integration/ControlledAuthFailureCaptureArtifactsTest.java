package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ControlledAuthFailureCaptureArtifactsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-10-02T03:00:00Z");
    private static final Instant FINISH = START.plusSeconds(2);
    private static final String SOURCE = "private-owned-auth-fixture";
    private static final String ALIAS = "account-" + "a".repeat(32);
    private static final String SCENARIO = "scenario-" + "b".repeat(32);
    private static final String PRIVATE = "private-token-body-username-sentinel";
    private static final long SPACING = Duration.ofMillis(210).toNanos();
    @TempDir Path temporary;
    private int directorySequence;

    @Test
    void retainsAllTargetFailuresAllClientStatusesAndOnlyCountsUnattributableEvents() throws Exception {
        Path output = freshOutput();
        write(output, events(), attempts(), SPACING, Set.of(PRIVATE));
        String eventText = Files.readString(output.resolve(ControlledAuthFailureCaptureArtifacts.EVENTS_FILE));
        List<JsonNode> exported = eventText.lines().map(ControlledAuthFailureCaptureArtifactsTest::read).toList();
        assertThat(exported).hasSize(4);
        for (int index = 0; index < exported.size(); index++) {
            JsonNode event = exported.get(index);
            Set<String> fields = new HashSet<>(); event.fieldNames().forEachRemaining(fields::add);
            assertThat(fields).isEqualTo(Set.of("account_alias", "event_sequence", "event_timestamp", "event_type",
                    "action", "outcome", "route_group", "source_ip", "user_agent_family"));
            assertThat(event.path("event_sequence").asInt()).isEqualTo(index);
            assertThat(event.path("account_alias").asText()).isEqualTo(ALIAS);
            assertThat(event.path("event_timestamp").asText()).isEqualTo(START.plusMillis((index + 1) * 210L + 5).toString());
            assertThat(event.path("event_type").asText()).isEqualTo("AUTH");
            assertThat(event.path("outcome").asText()).isEqualTo("FAILURE");
        }
        JsonNode evidence = read(Files.readString(output.resolve(ControlledAuthFailureCaptureArtifacts.EVIDENCE_FILE)));
        assertThat(evidence.path("capture_contract_version").asInt()).isEqualTo(2);
        assertThat(evidence.path("observed_account_event_count").asInt()).isEqualTo(4);
        assertThat(evidence.path("captured_auth_event_count").asInt()).isEqualTo(6);
        assertThat(evidence.path("client_request_count").asInt()).isEqualTo(7);
        assertThat(evidence.path("unattributable_auth_outcome_counts")).isEqualTo(read("{\"FAILURE\":1,\"RATE_LIMITED\":1}"));
        assertThat(evidence.path("client_http_status_counts")).isEqualTo(read("{\"200\":1,\"401\":5,\"429\":1}"));
        assertThat(evidence.path("attribution_kind").asText()).isEqualTo("TARGET_ASSOCIATED_UNAUTHENTICATED");
        assertThat(evidence.path("authenticated_actor_claimed").asBoolean()).isFalse();
        assertThat(evidence.path("coverage_session").asText()).isEqualTo("NO_DATA");
        assertThat(evidence.path("feature_sanity_counts").path("failed_login_count").asDouble()).isEqualTo(4.0);
        assertThat(evidence.path("feature_sanity_counts").path("failed_login_peak_60s").asDouble()).isEqualTo(4.0);
        assertThat(evidence.path("feature_sanity_counts").path("session_metadata_count").asDouble()).isZero();
        assertThat(evidence.path("missing_login_auth_event_count").asInt()).isZero();
        assertThat(evidence.path("missing_rate_limit_event_count").asInt()).isZero();
        assertThat(evidence.path("limiter_bypassed_or_reset").asBoolean()).isFalse();
        assertThat(evidence.path("timestamps_rewritten").asBoolean()).isFalse();
        assertThat(evidence.path("elapsed_window_closure_proven").asBoolean()).isFalse();
        JsonNode ledger = read(Files.readString(output.resolve(ControlledAuthFailureCaptureArtifacts.ATTEMPTS_FILE)));
        assertThat(ledger.path("attempts")).hasSize(7);
        assertThat(ledger.path("attempts").get(6).path("http_status").asInt()).isEqualTo(429);
        JsonNode scenario = read(Files.readString(output.resolve(ControlledAuthFailureCaptureArtifacts.SCENARIOS_FILE)))
                .path("scenarios").get(0);
        assertThat(scenario.path("planned_cause").asText()).isEqualTo("KNOWN_OWNED_USER_WRONG_PASSWORD");
        assertThat(scenario.path("expected_label").asText()).isEqualTo("OWNED_AUTH_FAILURE");
        assertThat(eventText).doesNotContain(SCENARIO, "OWNED_AUTH_FAILURE", "TARGET_ASSOCIATED_UNAUTHENTICATED",
                "planned_cause", "http_status", "session", "actor", "target");
        assertThat(Files.getPosixFilePermissions(output)).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        try (var files = Files.list(output)) {
            for (Path file : files.toList()) {
                String content = Files.readString(file);
                assertThat(content).doesNotContain(SOURCE, PRIVATE, "private-source-event-", "/api/", "access_token", "Bearer ");
                assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
            }
        }
        for (var entry : java.util.Map.of("trace_events_sha256", ControlledAuthFailureCaptureArtifacts.EVENTS_FILE,
                "scenarios_sha256", ControlledAuthFailureCaptureArtifacts.SCENARIOS_FILE,
                "client_http_attempts_sha256", ControlledAuthFailureCaptureArtifacts.ATTEMPTS_FILE).entrySet()) {
            assertThat(evidence.path(entry.getKey()).asText()).isEqualTo(
                    ControlledTraceCaptureArtifacts.sha256(Files.readString(output.resolve(entry.getValue()))));
        }
    }

    @Test
    void rejectsInventedAuthenticatedActorsSessionsHttpFieldsOrUnownedTargetsBeforeWriting() throws Exception {
        for (Consumer<SiemSecurityEvent> mutation : List.<Consumer<SiemSecurityEvent>>of(
                event -> event.setActorUserId(SOURCE), event -> event.setTargetUserId("unowned-target"),
                event -> event.setDemoLabel("ABNORMAL"), event -> event.setSessionPseudonym("c".repeat(64)),
                event -> event.setSessionIssuedAt(START.atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setHttpMethod("POST"), event -> event.setHttpStatus(401),
                event -> event.setEndpointCategory("LOGIN"), event -> event.setTelemetryContractVersion(3),
                event -> event.setSourceIp("203.0.113.1"), event -> event.setUserAgentFamily(PRIVATE),
                event -> event.setRouteGroup("/api/auth/login"),
                event -> event.setEventTimestamp(START.minusSeconds(1).atOffset(ZoneOffset.UTC).toLocalDateTime()))) {
            List<SiemSecurityEvent> source = events(); mutation.accept(source.get(0));
            rejected(source, attempts(), SPACING, Set.of(PRIVATE));
        }
        List<SiemSecurityEvent> limited = events(); limited.get(5).setTargetUserId(SOURCE);
        rejected(limited, attempts(), SPACING, Set.of(PRIVATE));
    }

    @Test
    void rejectsMissingLimitedUnknownOrOwnedSourceEventsDuplicateEventsAndBadClientConservation() throws Exception {
        for (int index : List.of(0, 4, 5)) {
            List<SiemSecurityEvent> source = events(); source.remove(index);
            rejected(source, attempts(), SPACING, Set.of(PRIVATE));
        }
        List<SiemSecurityEvent> duplicates = events(); duplicates.get(5).setId(duplicates.get(4).getId());
        rejected(duplicates, attempts(), SPACING, Set.of(PRIVATE));
        List<SiemSecurityEvent> fabricated = events(); fabricated.get(4).setTargetUserId(SOURCE);
        rejected(fabricated, attempts(), SPACING, Set.of(PRIVATE));
        List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> missing = attempts(); missing.remove(6);
        rejected(events(), missing, SPACING, Set.of(PRIVATE));
        List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> wrongStatus = attempts();
        var sixth = wrongStatus.get(6);
        wrongStatus.set(6, new ControlledAuthFailureCaptureArtifacts.HttpAttempt(6, sixth.requestedAt(), sixth.respondedAt(),
                "LOGIN_POST", 401));
        rejected(events(), wrongStatus, SPACING, Set.of(PRIVATE));
        rejected(events(), attempts(), Duration.ofMillis(200).toNanos() - 1, Set.of(PRIVATE));
    }

    @Test
    void failsClosedOnPrivacySentinelAndOutsideRealMinuteWithoutWritingFiles() throws Exception {
        rejected(events(), attempts(), SPACING, Set.of(ALIAS));
        rejected(events(), attempts(), SPACING, Set.of(" "));
        Path output = freshOutput();
        assertThatThrownBy(() -> ControlledAuthFailureCaptureArtifacts.write(output, JSON, events(), SOURCE, ALIAS, SCENARIO,
                START, START.plusSeconds(60), attempts(), SPACING, Set.of(PRIVATE))).isInstanceOf(IllegalArgumentException.class);
        try (var files = Files.list(output)) { assertThat(files).isEmpty(); }
    }

    private void rejected(List<SiemSecurityEvent> events, List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> attempts,
                          long spacing, Set<String> excluded) throws Exception {
        Path output = freshOutput();
        assertThatThrownBy(() -> write(output, events, attempts, spacing, excluded)).isInstanceOf(IllegalArgumentException.class);
        try (var files = Files.list(output)) { assertThat(files).isEmpty(); }
    }

    private Path freshOutput() throws Exception {
        Path project = Files.createDirectory(temporary.resolve("project-" + directorySequence++)).toRealPath();
        Files.createDirectory(project.resolve("backend")); Files.createFile(project.resolve("backend/pom.xml"));
        Files.createDirectory(project.resolve("observability"));
        return ControlledAuthFailureCaptureArtifacts.createFreshPrivateDirectory(project,
                project.resolve("observability/runtime/auth-capture").toString());
    }

    private static void write(Path output, List<SiemSecurityEvent> events,
                              List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> attempts,
                              long spacing, Set<String> excluded) throws Exception {
        ControlledAuthFailureCaptureArtifacts.write(output, JSON, events, SOURCE, ALIAS, SCENARIO,
                START, FINISH, attempts, spacing, excluded);
    }

    private static List<ControlledAuthFailureCaptureArtifacts.HttpAttempt> attempts() {
        var attempts = new ArrayList<ControlledAuthFailureCaptureArtifacts.HttpAttempt>();
        for (int index = 0; index < 7; index++) {
            Instant requestedAt = START.plusMillis(index * 210L);
            attempts.add(new ControlledAuthFailureCaptureArtifacts.HttpAttempt(index, requestedAt, requestedAt.plusMillis(10),
                    index == 0 ? "CSRF_READ" : "LOGIN_POST", index == 0 ? 200 : index == 6 ? 429 : 401));
        }
        return attempts;
    }

    private static List<SiemSecurityEvent> events() {
        List<SiemSecurityEvent> events = new ArrayList<>();
        for (int index = 0; index < 6; index++) {
            var event = new SiemSecurityEvent(); event.setId("private-source-event-" + index);
            event.setEventTimestamp(START.plusMillis((index + 1) * 210L + 5).atOffset(ZoneOffset.UTC).toLocalDateTime());
            event.setEventType("AUTH"); event.setAction("LOGIN"); event.setOutcome(index == 5 ? "RATE_LIMITED" : "FAILURE");
            event.setTargetUserId(index < 4 ? SOURCE : null); event.setRouteGroup("auth");
            event.setSourceIp("127.0.0.1"); event.setUserAgentFamily("FIREFOX"); events.add(event);
        }
        return events;
    }

    private static JsonNode read(String text) {
        try { return JSON.readTree(text); }
        catch (Exception exception) { throw new AssertionError(exception); }
    }
}
