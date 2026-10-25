package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.controller.OwnedLabControlledFaultController;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.TestComponent;

class ControlledOperationalCaptureArtifactsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-10-02T03:00:00Z");
    private static final Instant FINISH = START.plusSeconds(4);
    private static final String ACTOR = "owned-source-private-account";
    private static final String ALIAS = "account-" + "a".repeat(32);
    private static final String SCENARIO = "scenario-" + "b".repeat(32);
    private static final String SESSION = "c".repeat(64);
    private static final String PRIVATE = "raw-body-query-token-private";
    private static final long SPACING = Duration.ofMillis(210).toNanos();
    private static final List<ControlledOperationalCaptureArtifacts.Scenario> SCENARIOS = List.of(
            new ControlledOperationalCaptureArtifacts.Scenario(ALIAS, SCENARIO, "OPERATIONAL_FAULT", "CONTROLLED_OPERATIONAL_ANOMALY"));
    @TempDir Path temporary;
    private int directorySequence;

    @Test void preservesReal503NormalRecoveryEventsPrivateAllowlistModesCountsHashesAndSeparateIntent() throws Exception {
        Path output = output();
        write(output, events(), ledger(), SPACING, Set.of(PRIVATE));
        String eventText = Files.readString(output.resolve(ControlledOperationalCaptureArtifacts.EVENTS_FILE));
        List<JsonNode> records = eventText.lines().map(this::json).toList();
        assertThat(records).hasSize(17);
        assertThat(records.stream().filter(record -> record.path("http_status").asInt() == 503)).hasSize(10);
        assertThat(records.stream().filter(record -> record.path("http_status").asInt() == 200)).hasSize(6);
        Set<String> common = Set.of("account_alias", "event_sequence", "event_timestamp", "event_type", "action", "outcome",
                "source_ip", "user_agent_family", "route_group");
        assertThat(fields(records.getFirst())).isEqualTo(common);
        Set<String> http = new HashSet<>(common);
        http.addAll(Set.of("http_method", "http_status", "telemetry_contract_version", "endpoint_category", "session_pseudonym", "session_issued_at"));
        for (int index = 1; index < records.size(); index++) {
            assertThat(fields(records.get(index))).isEqualTo(http);
            assertThat(records.get(index).path("event_sequence").asInt()).isEqualTo(index);
            assertThat(records.get(index).path("telemetry_contract_version").asInt()).isEqualTo(3);
            assertThat(records.get(index).path("session_pseudonym").asText()).isEqualTo(SESSION);
        }
        assertThat(records.get(6).path("event_timestamp").asText()).isEqualTo(START.plusMillis(1480).toString());
        assertThat(records.getLast().path("http_status").asInt()).isEqualTo(200);
        assertThat(eventText).doesNotContain("CONTROLLED_OPERATIONAL_ANOMALY", "expected_label", "request_kind", SCENARIO, PRIVATE, ACTOR, "/api/");
        String scenarioText = Files.readString(output.resolve(ControlledOperationalCaptureArtifacts.SCENARIOS_FILE));
        JsonNode scenarioRoot = json(scenarioText);
        assertThat(scenarioRoot.path("capture_contract_version").asInt()).isEqualTo(2);
        assertThat(scenarioRoot.path("labels_separate_from_events").asBoolean()).isTrue();
        JsonNode scenario = scenarioRoot.path("scenarios").get(0);
        assertThat(scenario.path("expected_label").asText()).isEqualTo("CONTROLLED_OPERATIONAL_ANOMALY");
        assertThat(scenario.path("observed_event_count").asInt()).isEqualTo(17);
        assertThat(scenario.path("observed_session_count").asInt()).isEqualTo(1);
        assertThat(scenario.path("malicious_caller_asserted").asBoolean()).isFalse();
        String clientText = Files.readString(output.resolve(ControlledOperationalCaptureArtifacts.CLIENT_LEDGER_FILE));
        assertThat(clientText.lines()).hasSize(18);
        JsonNode evidence = json(Files.readString(output.resolve(ControlledOperationalCaptureArtifacts.EVIDENCE_FILE)));
        assertThat(evidence.path("capture_contract_version").asInt()).isEqualTo(2);
        assertThat(evidence.path("event_type_counts")).isEqualTo(json("{\"AUTH\":1,\"HTTP_REQUEST\":16}"));
        assertThat(evidence.path("server_http_status_counts")).isEqualTo(json("{\"200\":6,\"503\":10}"));
        assertThat(evidence.path("client_http_status_counts")).isEqualTo(evidence.path("server_http_status_counts"));
        assertThat(evidence.path("client_request_count").asInt()).isEqualTo(18);
        assertThat(evidence.path("client_ledger_file").asText()).isEqualTo(ControlledOperationalCaptureArtifacts.CLIENT_LEDGER_FILE);
        assertThat(evidence.path("trace_events_sha256").asText()).isEqualTo(ControlledTraceCaptureArtifacts.sha256(eventText));
        assertThat(evidence.path("scenarios_sha256").asText()).isEqualTo(ControlledTraceCaptureArtifacts.sha256(scenarioText));
        assertThat(evidence.path("client_ledger_sha256").asText()).isEqualTo(ControlledTraceCaptureArtifacts.sha256(clientText));
        for (String claim : List.of("malicious_caller_asserted", "attack_confirmation", "dos_or_disruption_demonstrated",
                "independent_accuracy_dataset", "elapsed_window_closure_proven", "timestamps_rewritten")) {
            assertThat(evidence.path(claim).asBoolean()).as(claim).isFalse();
        }
        assertThat(evidence.path("actual_5xx_proof").asText()).isEqualTo("CONTROLLED_OPERATIONAL_ANOMALY_ONLY");
        assertThat(Files.getPosixFilePermissions(output)).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        try (var files = Files.list(output)) {
            for (Path file : files.toList()) assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        }
    }

    @Test void rejectsUnownedRawUnverifiedMisclassifiedOrDroppedEvidenceBeforeWriting() throws Exception {
        for (Consumer<SiemSecurityEvent> mutation : List.<Consumer<SiemSecurityEvent>>of(
                event -> event.setActorUserId("other-private-account"), event -> event.setDemoLabel("MALICIOUS"),
                event -> event.setSourceIp("203.0.113.9"), event -> event.setUserAgentFamily(PRIVATE),
                event -> event.setRouteGroup("/api/private"), event -> event.setSessionPseudonym(null),
                event -> event.setSessionIssuedAt(null), event -> event.setSessionIssuedAt(FINISH.atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setTelemetryContractVersion(2), event -> event.setEndpointCategory("UNRESOLVED"),
                event -> event.setOutcome("SUCCESS"), event -> event.setEventTimestamp(START.minusSeconds(1).atOffset(ZoneOffset.UTC).toLocalDateTime()))) {
            List<SiemSecurityEvent> altered = events(); mutation.accept(altered.get(6));
            reject(altered, ledger(), SPACING, Set.of(PRIVATE));
        }
        List<SiemSecurityEvent> missing = events(); missing.remove(6); reject(missing, ledger(), SPACING, Set.of(PRIVATE));
        List<SiemSecurityEvent> duplicate = events(); duplicate.get(6).setId(duplicate.get(5).getId()); reject(duplicate, ledger(), SPACING, Set.of(PRIVATE));
        List<ControlledOperationalCaptureArtifacts.ClientObservation> missingPlan = ledger(); missingPlan.remove(7);
        reject(events(), missingPlan, SPACING, Set.of(PRIVATE));
        List<ControlledOperationalCaptureArtifacts.ClientObservation> misordered = ledger();
        var normal = misordered.get(2); misordered.set(2, misordered.get(7)); misordered.set(7, normal);
        reject(events(), misordered, SPACING, Set.of(PRIVATE));
    }

    @Test void rejectsPrivacyRateWindowAndOverwriteViolationsAndUnwarrantedMaliciousLabels() throws Exception {
        reject(events(), ledger(), SPACING, Set.of(SESSION));
        reject(events(), ledger(), SPACING, Set.of());
        reject(events(), ledger(), Duration.ofMillis(199).toNanos(), Set.of(PRIVATE));
        Path output = output();
        assertThatThrownBy(() -> ControlledOperationalCaptureArtifacts.write(output, JSON, events(), Map.of(ACTOR, ALIAS),
                SCENARIOS, ledger(), START, START.plusSeconds(61), SPACING, Set.of(PRIVATE))).isInstanceOf(IllegalArgumentException.class);
        assertEmpty(output);
        Path complete = output(); write(complete, events(), ledger(), SPACING, Set.of(PRIVATE));
        assertThatThrownBy(() -> write(complete, events(), ledger(), SPACING, Set.of(PRIVATE))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ControlledOperationalCaptureArtifacts.Scenario(ALIAS, SCENARIO, "OPERATIONAL_FAULT", "MALICIOUS"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ControlledOperationalCaptureArtifacts.Scenario(ALIAS, SCENARIO, "OWNED_RESOURCE_PROBE", "DOS_ATTACK"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void faultControllerIsTestComponentWithSafeExistingExceptionAndNoProductionSource() {
        assertThat(OwnedLabControlledFaultController.class.isAnnotationPresent(TestComponent.class)).isTrue();
        assertThatThrownBy(() -> new OwnedLabControlledFaultController().controlledFault())
                .isInstanceOf(ServiceUnavailableException.class).hasMessage("Controlled owned local test service unavailable.");
    }

    private List<ControlledOperationalCaptureArtifacts.ClientObservation> ledger() {
        List<ControlledOperationalCaptureArtifacts.ClientObservation> ledger = new ArrayList<>();
        ledger.add(observation(0, "CSRF_READ", 200)); ledger.add(observation(1, "LOGIN", 200));
        for (int index = 0; index < 5; index++) ledger.add(observation(index + 2, "NORMAL_READ", 200));
        for (int index = 0; index < 10; index++) ledger.add(observation(index + 7, "CONTROLLED_FAULT", 503));
        ledger.add(observation(17, "AFTER_FAULT_NORMAL_READ", 200));
        return ledger;
    }
    private ControlledOperationalCaptureArtifacts.ClientObservation observation(int sequence, String kind, int status) {
        return new ControlledOperationalCaptureArtifacts.ClientObservation(ALIAS, START.plusMillis(sequence * 210L), kind,
                "LOGIN".equals(kind) ? "POST" : "GET", status, status);
    }
    private List<SiemSecurityEvent> events() {
        List<SiemSecurityEvent> events = new ArrayList<>();
        SiemSecurityEvent login = base("private-login-event", START.plusMillis(220));
        login.setEventType("AUTH"); login.setAction("LOGIN"); login.setOutcome("SUCCESS"); login.setRouteGroup("auth"); events.add(login);
        for (var observation : ledger()) {
            if (!observation.capturedHttp()) continue;
            SiemSecurityEvent event = base("private-source-event-" + events.size(), observation.sentAt().plusMillis(10));
            event.setEventType("HTTP_REQUEST"); event.setAction("API_REQUEST"); event.setHttpMethod("GET"); event.setHttpStatus(observation.observedStatus());
            event.setOutcome(observation.observedStatus() == 503 ? "FAILURE" : "SUCCESS");
            event.setRouteGroup(observation.observedStatus() == 503 ? "other_api" : "products");
            event.setEndpointCategory(observation.observedStatus() == 503 ? "OTHER_MATCHED" : "PRODUCT_LIST");
            event.setTelemetryContractVersion(3); event.setSessionPseudonym(SESSION); event.setSessionIssuedAt(START.atOffset(ZoneOffset.UTC).toLocalDateTime());
            events.add(event);
        }
        return events;
    }
    private SiemSecurityEvent base(String id, Instant timestamp) {
        SiemSecurityEvent event = new SiemSecurityEvent(); event.setId(id); event.setActorUserId(ACTOR); event.setTraceId(PRIVATE);
        event.setSourceIp("127.0.0.1"); event.setUserAgentFamily("FIREFOX"); event.setEventTimestamp(timestamp.atOffset(ZoneOffset.UTC).toLocalDateTime());
        return event;
    }
    private Path output() throws Exception {
        Path project = Files.createDirectory(temporary.resolve("project-" + directorySequence++));
        Files.createDirectory(project.resolve("backend")); Files.createFile(project.resolve("backend/pom.xml")); Files.createDirectory(project.resolve("observability"));
        return ControlledOperationalCaptureArtifacts.createFreshPrivateDirectory(project, project.resolve("observability/runtime/operational").toString());
    }
    private void write(Path output, List<SiemSecurityEvent> events, List<ControlledOperationalCaptureArtifacts.ClientObservation> ledger,
                       long spacing, Set<String> forbidden) throws Exception {
        ControlledOperationalCaptureArtifacts.write(output, JSON, events, Map.of(ACTOR, ALIAS), SCENARIOS, ledger, START, FINISH, spacing, forbidden);
    }
    private void reject(List<SiemSecurityEvent> events, List<ControlledOperationalCaptureArtifacts.ClientObservation> ledger,
                        long spacing, Set<String> forbidden) throws Exception {
        Path output = output();
        assertThatThrownBy(() -> write(output, events, ledger, spacing, forbidden)).isInstanceOf(IllegalArgumentException.class); assertEmpty(output);
    }
    private void assertEmpty(Path output) throws Exception {
        try (var files = Files.list(output)) { assertThat(files).isEmpty(); }
    }
    private JsonNode json(String value) {
        try { return JSON.readTree(value); } catch (Exception failure) { throw new AssertionError(failure); }
    }
    private Set<String> fields(JsonNode node) {
        Set<String> names = new HashSet<>(); node.fieldNames().forEachRemaining(names::add); return names;
    }
}
