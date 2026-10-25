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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SensitiveActionControlledCaptureArtifactsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-10-02T03:00:00Z");
    private static final Instant FINISH = START.plusSeconds(6);
    private static final String SOURCE = "private-owned-account-id";
    private static final String ALIAS = "account-" + "a".repeat(32);
    private static final String SCENARIO = "scenario-" + "b".repeat(32);
    private static final String PRIVATE = "private-credential-or-token-canary";
    private static final long SPACING = Duration.ofMillis(210).toNanos();
    private static final List<SensitiveActionControlledCaptureArtifacts.Scenario> SCENARIOS = List.of(
            new SensitiveActionControlledCaptureArtifacts.Scenario(ALIAS, SCENARIO,
                    "BENIGN_PASSWORD_CHANGE", "BENIGN", "OWNED_PASSWORD_MAINTENANCE"));
    @TempDir Path temporary;
    private int outputSequence;

    @Test void writesActualDomainNullsPairedHttpMetadataIndependentLedgerAndHashesWithoutAttackClaims() throws Exception {
        Path output = output(); write(output, events(), attempts(), Set.of(PRIVATE));
        String eventText = Files.readString(output.resolve(SensitiveActionControlledCaptureArtifacts.EVENTS_FILE));
        List<JsonNode> rows = parse(eventText);
        assertThat(rows).hasSize(6);
        JsonNode domain = rows.stream().filter(row -> "DOMAIN_ACTION".equals(row.path("event_type").asText())).findFirst().orElseThrow();
        assertThat(domain.path("action").asText()).isEqualTo("PASSWORD_CHANGE");
        assertThat(domain.path("source_ip").isNull()).isTrue();
        assertThat(domain.path("user_agent_family").isNull()).isTrue();
        assertThat(domain.has("session_pseudonym")).isFalse();
        assertThat(domain.has("session_issued_at")).isFalse();
        assertThat(domain.has("http_method")).isFalse();
        assertThat(domain.has("http_status")).isFalse();
        assertThat(domain.path("event_timestamp").asText()).isEqualTo(START.plusMillis(900).toString());
        assertThat(rows.stream().filter(row -> "HTTP_REQUEST".equals(row.path("event_type").asText()))
                .allMatch(row -> row.path("telemetry_contract_version").asInt() == UebaSessionTelemetry.CONTRACT_VERSION
                        && row.has("session_pseudonym") && row.has("session_issued_at"))).isTrue();
        assertThat(eventText).doesNotContain(SOURCE, PRIVATE, SCENARIO, "planned_cause", "expected_label", "BENIGN", "/api/", "jti");
        String ledgerText = Files.readString(output.resolve(SensitiveActionControlledCaptureArtifacts.ATTEMPTS_FILE));
        JsonNode revoked = parse(ledgerText).stream().filter(row -> row.path("http_status").asInt() == 401).findFirst().orElseThrow();
        assertThat(revoked.path("attempt_kind").asText()).isEqualTo("REVOKED_SESSION_ATTEMPT");
        assertThat(revoked.path("intended_account_alias").asText()).isEqualTo(ALIAS);
        assertThat(revoked.path("provenance").asText()).isEqualTo("CLIENT_OBSERVED_NOT_SERVER_ATTRIBUTION");
        String scenarioText = Files.readString(output.resolve(SensitiveActionControlledCaptureArtifacts.SCENARIOS_FILE));
        assertThat(JSON.readTree(scenarioText).path("scenarios").get(0).path("expected_label").asText()).isEqualTo("BENIGN");
        JsonNode evidence = JSON.readTree(Files.readString(output.resolve(SensitiveActionControlledCaptureArtifacts.EVIDENCE_FILE)));
        assertThat(evidence.path("capture_contract_version").asInt()).isEqualTo(2);
        assertThat(evidence.path("event_type_counts")).isEqualTo(JSON.readTree("{\"AUTH\":2,\"DOMAIN_ACTION\":1,\"HTTP_REQUEST\":3}"));
        assertThat(evidence.path("event_count").asInt()).isEqualTo(6);
        assertThat(evidence.path("client_request_count").asInt()).isEqualTo(9);
        assertThat(evidence.path("all_client_requests_equal_server_events").asBoolean()).isFalse();
        assertThat(evidence.path("attributed_http_auth_domain_conservation").asBoolean()).isTrue();
        assertThat(evidence.path("revoked_attempt_server_account_attribution").asText()).isEqualTo("NOT_OBSERVED_NOT_FABRICATED");
        assertThat(evidence.path("sensitive_action_abuse_qualification").asText()).isEqualTo("NOT_ESTABLISHED_REQUIRES_VALID_ABUSE_PROTOCOL");
        assertThat(evidence.path("qualification_readiness").asText()).isEqualTo("COLD_NOT_READY");
        assertThat(evidence.path("timestamps_rewritten").asBoolean()).isFalse();
        assertThat(evidence.path("trace_events_sha256").asText()).isEqualTo(SensitiveActionControlledCaptureArtifacts.sha256(eventText));
        assertThat(evidence.path("scenarios_sha256").asText()).isEqualTo(SensitiveActionControlledCaptureArtifacts.sha256(scenarioText));
        assertThat(evidence.path("client_ledger_file").asText()).isEqualTo(SensitiveActionControlledCaptureArtifacts.ATTEMPTS_FILE);
        assertThat(evidence.path("client_ledger_sha256").asText()).isEqualTo(SensitiveActionControlledCaptureArtifacts.sha256(ledgerText));
        try (var stream = Files.list(output)) {
            List<Path> files = stream.toList(); assertThat(files).hasSize(4);
            for (Path file : files) assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        }
    }

    @Test void leavesMissingSessionPairMissingRatherThanManufacturingAttribution() throws Exception {
        List<SiemSecurityEvent> source = events();
        source.get(1).setSessionPseudonym(null); source.get(1).setSessionIssuedAt(null);
        Path output = output(); write(output, source, attempts(), Set.of(PRIVATE));
        JsonNode row = parse(Files.readString(output.resolve(SensitiveActionControlledCaptureArtifacts.EVENTS_FILE))).get(1);
        assertThat(row.has("session_pseudonym")).isFalse(); assertThat(row.has("session_issued_at")).isFalse();
    }

    @Test void rejectsInventedDomainContextAndAuthSessionFieldsBeforeWriting() throws Exception {
        for (Consumer<SiemSecurityEvent> change : List.<Consumer<SiemSecurityEvent>>of(
                event -> event.setSourceIp("127.0.0.1"), event -> event.setUserAgentFamily("FIREFOX"),
                event -> event.setSessionPseudonym("c".repeat(64)), event -> event.setHttpMethod("PUT"),
                event -> event.setTelemetryContractVersion(UebaSessionTelemetry.CONTRACT_VERSION))) {
            List<SiemSecurityEvent> source = events(); change.accept(source.get(2)); rejected(source, attempts(), Set.of(PRIVATE));
        }
        List<SiemSecurityEvent> source = events(); source.get(0).setSessionPseudonym("c".repeat(64));
        rejected(source, attempts(), Set.of(PRIVATE));
    }

    @Test void rejectsPrivateUnownedLabelledFutureDuplicateAndMalformedHttpFields() throws Exception {
        for (Consumer<SiemSecurityEvent> change : List.<Consumer<SiemSecurityEvent>>of(
                event -> event.setActorUserId("unowned"), event -> event.setTargetUserId("other"), event -> event.setDemoLabel("NORMAL"),
                event -> event.setEventTimestamp(FINISH.plusSeconds(1).atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setSourceIp("198.51.100.2"), event -> event.setUserAgentFamily(PRIVATE),
                event -> event.setEndpointCategory("UNMATCHED"), event -> event.setSessionIssuedAt(null),
                event -> event.setSessionIssuedAt(FINISH.atOffset(ZoneOffset.UTC).toLocalDateTime()),
                event -> event.setSessionPseudonym("Bearer " + PRIVATE))) {
            List<SiemSecurityEvent> source = events(); change.accept(source.get(1)); rejected(source, attempts(), Set.of(PRIVATE));
        }
        List<SiemSecurityEvent> duplicate = events(); duplicate.get(1).setId(duplicate.get(0).getId());
        rejected(duplicate, attempts(), Set.of(PRIVATE));
        rejected(events(), attempts(), Set.of("c".repeat(64))); rejected(events(), attempts(), Set.of());
    }

    @Test void rejectsDropped401AttemptAndMismatchedAuthDomainOrHttpConservation() throws Exception {
        List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> dropped = new ArrayList<>(attempts()); dropped.remove(5);
        rejected(events(), dropped, Set.of(PRIVATE));
        List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> missingRefresh = new ArrayList<>(attempts()); missingRefresh.remove(3);
        rejected(events(), missingRefresh, Set.of(PRIVATE));
        for (int index : List.of(0, 1, 2)) {
            List<SiemSecurityEvent> source = events(); source.remove(index); rejected(source, attempts(), Set.of(PRIVATE));
        }
    }

    @Test void requiresFreshPrivateDirectChildAndRefusesSymlinksOrOverwrite() throws Exception {
        Path root = Files.createDirectory(temporary.resolve("project")); Files.createDirectory(root.resolve("backend"));
        Files.createFile(root.resolve("backend/pom.xml")); Files.createDirectory(root.resolve("observability"));
        Path target = root.resolve("observability/runtime/fresh");
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(root, target.toString());
        assertThat(Files.getPosixFilePermissions(output)).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        assertThatThrownBy(() -> SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(root, target.toString()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(root,
                root.resolve("observability/runtime/nested/output").toString())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(root, "relative"))
                .isInstanceOf(IllegalArgumentException.class);
        Path link = root.resolve("observability/runtime/link"); Files.createSymbolicLink(link, output);
        assertThatThrownBy(() -> SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(root, link.toString()))
                .isInstanceOf(IllegalArgumentException.class);
        write(output, events(), attempts(), Set.of(PRIVATE));
        assertThatThrownBy(() -> write(output, events(), attempts(), Set.of(PRIVATE))).isInstanceOf(IllegalArgumentException.class);
    }

    private Path output() throws Exception {
        return Files.createDirectory(temporary.resolve("output-" + outputSequence++),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    private void rejected(List<SiemSecurityEvent> source, List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> ledger,
                          Set<String> exclusions) throws Exception {
        Path output = output(); assertThatThrownBy(() -> write(output, source, ledger, exclusions)).isInstanceOf(IllegalArgumentException.class);
        try (var files = Files.list(output)) { assertThat(files.count()).isZero(); }
    }
    private static void write(Path output, List<SiemSecurityEvent> source,
                              List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> ledger, Set<String> exclusions) throws Exception {
        SensitiveActionControlledCaptureArtifacts.write(output, JSON, source, Map.of(SOURCE, ALIAS), SCENARIOS,
                ledger, START, FINISH, SPACING, exclusions);
    }
    private static List<JsonNode> parse(String text) {
        return text.lines().map(line -> { try { return JSON.readTree(line); } catch (Exception failure) { throw new AssertionError(failure); } }).toList();
    }
    private static List<SiemSecurityEvent> events() {
        return new ArrayList<>(List.of(auth("auth-1", 200), http("http-1", 500, "GET", 200, "c"),
                domain(), http("http-2", 1000, "PUT", 204, "c"), auth("auth-2", 2000), http("http-3", 2500, "GET", 200, "d")));
    }
    private static SiemSecurityEvent base(String id, long millis, String type, String action, String group) {
        SiemSecurityEvent event = new SiemSecurityEvent(); event.setId(id); event.setActorUserId(SOURCE);
        event.setEventTimestamp(START.plusMillis(millis).atOffset(ZoneOffset.UTC).toLocalDateTime());
        event.setEventType(type); event.setAction(action); event.setOutcome("SUCCESS"); event.setRouteGroup(group);
        event.setTraceId(PRIVATE); return event;
    }
    private static SiemSecurityEvent auth(String id, long millis) {
        SiemSecurityEvent event = base(id, millis, "AUTH", "LOGIN", "auth"); event.setTargetUserId(SOURCE);
        event.setSourceIp("127.0.0.1"); event.setUserAgentFamily("FIREFOX"); return event;
    }
    private static SiemSecurityEvent domain() {
        SiemSecurityEvent event = base("domain-1", 900, "DOMAIN_ACTION", "PASSWORD_CHANGE", "account");
        event.setTargetUserId(SOURCE); return event;
    }
    private static SiemSecurityEvent http(String id, long millis, String method, int status, String session) {
        SiemSecurityEvent event = base(id, millis, "HTTP_REQUEST", "API_REQUEST", "profile");
        event.setSourceIp("127.0.0.1"); event.setUserAgentFamily("FIREFOX"); event.setHttpMethod(method); event.setHttpStatus(status);
        event.setTelemetryContractVersion(UebaSessionTelemetry.CONTRACT_VERSION);
        event.setEndpointCategory("GET".equals(method) ? "PROFILE_READ" : "PROFILE_PASSWORD");
        event.setSessionPseudonym(session.repeat(64)); event.setSessionIssuedAt(START.atOffset(ZoneOffset.UTC).toLocalDateTime()); return event;
    }
    private static List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> attempts() {
        String[] kinds = {"CSRF_READ", "LOGIN", "CURRENT_SESSION_REQUEST", "CSRF_REFRESH", "CURRENT_SESSION_REQUEST",
                "REVOKED_SESSION_ATTEMPT", "CSRF_READ", "LOGIN", "CURRENT_SESSION_REQUEST"};
        String[] methods = {"GET", "POST", "GET", "GET", "PUT", "GET", "GET", "POST", "GET"};
        int[] statuses = {200, 200, 200, 200, 204, 401, 200, 200, 200};
        List<SensitiveActionControlledCaptureArtifacts.ClientAttempt> result = new ArrayList<>();
        for (int index = 0; index < kinds.length; index++) result.add(new SensitiveActionControlledCaptureArtifacts.ClientAttempt(index,
                ALIAS, START.plusMillis(index * 210L), kinds[index], methods[index],
                Set.of("CSRF_READ", "CSRF_REFRESH", "LOGIN").contains(kinds[index]) ? "auth" : "profile", statuses[index]));
        return result;
    }
}
