package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.service.siem.AccountBaselinePolicy;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.ContextualBehaviorFeatures;
import com.flarefitness.backend.service.siem.SecurityEventNormalizer;
import com.flarefitness.backend.service.siem.SessionEndpointBehaviorFeatures;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Test-only V2 AUTH capture. Unknown and throttled requests are counts, never invented account events. */
final class ControlledAuthFailureCaptureArtifacts {
    static final int CONTRACT_VERSION = 2;
    static final String EVENTS_FILE = "trace-events.ndjson";
    static final String SCENARIOS_FILE = "scenarios.json";
    static final String EVIDENCE_FILE = "capture-evidence.json";
    static final String ATTEMPTS_FILE = "client-http-attempts.json";
    private static final String ATTRIBUTION = "TARGET_ASSOCIATED_UNAUTHENTICATED";

    record HttpAttempt(int sequence, Instant requestedAt, Instant respondedAt, String operation, int status) {
        HttpAttempt {
            require(sequence >= 0 && requestedAt != null && respondedAt != null && !respondedAt.isBefore(requestedAt),
                    "Actual ordered request and response timestamps required");
            require(Set.of("CSRF_READ", "LOGIN_POST").contains(operation) && status >= 100 && status <= 599,
                    "Allowlisted operation and actual HTTP status required");
        }
    }

    private ControlledAuthFailureCaptureArtifacts() { }

    static Path createFreshPrivateDirectory(Path projectRoot, String requestedDirectory) throws Exception {
        return ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(projectRoot, requestedDirectory);
    }

    static void write(Path output, ObjectMapper mapper, List<SiemSecurityEvent> captured,
                      String sourceAccount, String accountAlias, String scenarioId,
                      Instant startedAt, Instant finishedAt, List<HttpAttempt> attempts,
                      long minimumSpacingNanos, Set<String> forbiddenPrivateValues) throws Exception {
        require(Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(output)
                        && Files.getPosixFilePermissions(output).equals(PosixFilePermissions.fromString("rwx------")),
                "Private non-symlink capture directory required");
        try (var files = Files.list(output)) { require(files.findAny().isEmpty(), "Fresh empty capture directory required"); }
        require(sourceAccount != null && !sourceAccount.isBlank()
                        && accountAlias != null && accountAlias.matches("account-[a-f0-9]{32}")
                        && scenarioId != null && scenarioId.matches("scenario-[a-f0-9]{32}"),
                "Private source account and opaque exported aliases required");
        require(startedAt != null && finishedAt != null && !finishedAt.isBefore(startedAt)
                        && Duration.between(startedAt, finishedAt).compareTo(Duration.ofSeconds(60)) < 0,
                "Capture must finish within the real minute budget");
        require(minimumSpacingNanos >= Duration.ofMillis(200).toNanos() && attempts.size() == 7,
                "One CSRF read and six bounded real login requests required");
        require(captured.size() == 6 && captured.stream().allMatch(event -> event != null && event.getId() != null)
                        && new HashSet<>(captured.stream().map(SiemSecurityEvent::getId).toList()).size() == captured.size(),
                "Exactly six distinct source AUTH events required");

        Map<Integer, Long> statuses = new TreeMap<>();
        var clientRoot = mapper.createObjectNode();
        clientRoot.put("capture_contract_version", CONTRACT_VERSION);
        clientRoot.put("scope", "OWNED_LOCAL_AUTH_HTTP_CLIENT_OBSERVATIONS");
        var clientArray = clientRoot.putArray("attempts");
        for (int index = 0; index < attempts.size(); index++) {
            HttpAttempt attempt = attempts.get(index);
            require(attempt.sequence() == index && !attempt.requestedAt().isBefore(startedAt)
                            && !attempt.respondedAt().isAfter(finishedAt)
                            && (index == 0 || !attempt.requestedAt().isBefore(attempts.get(index - 1).respondedAt())),
                    "Every actual HTTP attempt must be retained in order within the capture");
            require(index == 0 ? "CSRF_READ".equals(attempt.operation()) && attempt.status() == 200
                            : "LOGIN_POST".equals(attempt.operation()) && attempt.status() == (index == 6 ? 429 : 401),
                    "Actual login failure and preserved sixth-attempt throttling contract required");
            var node = clientArray.addObject();
            node.put("attempt_sequence", index); node.put("request_timestamp", attempt.requestedAt().toString());
            node.put("response_timestamp", attempt.respondedAt().toString());
            node.put("operation", attempt.operation()); node.put("http_status", attempt.status());
            statuses.merge(attempt.status(), 1L, Long::sum);
        }

        List<SiemSecurityEvent> owned = new ArrayList<>();
        Map<String, Long> unattributable = new TreeMap<>();
        for (SiemSecurityEvent event : captured) {
            require("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction())
                            && Set.of("FAILURE", "RATE_LIMITED").contains(event.getOutcome())
                            && "auth".equals(event.getRouteGroup()) && event.getActorUserId() == null
                            && event.getDemoLabel() == null, "Only actual unauthenticated AUTH telemetry allowed");
            require(event.getEventTimestamp() != null, "Actual source timestamp required");
            Instant timestamp = event.getEventTimestamp().toInstant(ZoneOffset.UTC);
            require(!timestamp.isBefore(startedAt) && !timestamp.isAfter(finishedAt)
                            && "127.0.0.1".equals(event.getSourceIp())
                            && SecurityEventNormalizer.AGENT_FAMILIES.contains(event.getUserAgentFamily()),
                    "Actual UTC loopback and normalized agent telemetry required");
            require(event.getHttpMethod() == null && event.getHttpStatus() == null
                            && event.getSessionPseudonym() == null && event.getSessionIssuedAt() == null
                            && event.getTelemetryContractVersion() == null && event.getEndpointCategory() == null,
                    "AUTH must not acquire invented HTTP, endpoint or authenticated session fields");
            if (event.getTargetUserId() == null) {
                unattributable.merge(event.getOutcome(), 1L, Long::sum);
            } else {
                require(sourceAccount.equals(event.getTargetUserId()) && "FAILURE".equals(event.getOutcome()),
                        "Only the verified owned target may receive an account alias");
                owned.add(event);
            }
        }
        require(owned.size() == 4 && unattributable.equals(Map.of("FAILURE", 1L, "RATE_LIMITED", 1L)),
                "No missing or reassigned known, unknown or limited AUTH events allowed");
        owned.sort(Comparator.comparing(SiemSecurityEvent::getEventTimestamp).thenComparing(SiemSecurityEvent::getId));
        StringBuilder eventText = new StringBuilder();
        for (int index = 0; index < owned.size(); index++) {
            SiemSecurityEvent event = owned.get(index);
            ObjectNode record = mapper.createObjectNode();
            record.put("account_alias", accountAlias); record.put("event_sequence", index);
            record.put("event_timestamp", event.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());
            record.put("event_type", event.getEventType()); record.put("action", event.getAction());
            record.put("outcome", event.getOutcome()); record.put("route_group", event.getRouteGroup());
            record.put("source_ip", event.getSourceIp()); record.put("user_agent_family", event.getUserAgentFamily());
            eventText.append(mapper.writeValueAsString(record)).append('\n');
        }
        Map<String, Double> sanity = verifyOpenWindowFeatureCounts(owned);
        var scenarioRoot = mapper.createObjectNode();
        scenarioRoot.put("schema_version", 2); scenarioRoot.put("capture_contract_version", CONTRACT_VERSION);
        scenarioRoot.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        scenarioRoot.put("labels_separate_from_events", true);
        var scenario = scenarioRoot.putArray("scenarios").addObject();
        scenario.put("account_alias", accountAlias); scenario.put("scenario_id", scenarioId);
        scenario.put("family", "OWNED_AUTH_FAILURE_GUESSTEST"); scenario.put("expected_label", "OWNED_AUTH_FAILURE");
        scenario.put("planned_cause", "KNOWN_OWNED_USER_WRONG_PASSWORD");
        scenario.put("attribution_kind", ATTRIBUTION); scenario.put("authenticated_actor_claimed", false);
        scenario.put("observed_account_event_count", owned.size()); scenario.put("observed_authenticated_session_count", 0);
        scenario.put("observed_event_count", owned.size());
        scenario.put("coverage_session", "NO_DATA");

        var evidence = mapper.createObjectNode();
        evidence.put("schema_version", 2); evidence.put("capture_contract_version", CONTRACT_VERSION);
        evidence.put("passed", true); evidence.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        evidence.put("scope", "OWNED_RANDOM_PORT_BACKEND_TESTCONTAINERS_MYSQL_REDIS_ONLY");
        evidence.put("capture_started_at", startedAt.toString()); evidence.put("capture_finished_at", finishedAt.toString());
        evidence.put("capture_duration_millis", Duration.between(startedAt, finishedAt).toMillis());
        evidence.put("client_request_count", attempts.size()); evidence.put("login_post_count", 6);
        evidence.put("captured_auth_event_count", captured.size()); evidence.put("observed_account_event_count", owned.size());
        evidence.put("event_count", owned.size()); evidence.set("event_type_counts", mapper.valueToTree(Map.of("AUTH", 4)));
        evidence.put("captured_http_request_event_count", 0); evidence.put("successful_login_count", 0);
        evidence.put("attribution_kind", ATTRIBUTION); evidence.put("authenticated_actor_claimed", false);
        evidence.set("unattributable_auth_outcome_counts", mapper.valueToTree(unattributable));
        evidence.put("unattributable_auth_event_count", 2); evidence.put("missing_login_auth_event_count", 0);
        evidence.put("observed_rate_limited_count", unattributable.get("RATE_LIMITED"));
        evidence.put("planned_rate_limit_check_count", 1); evidence.put("missing_rate_limit_event_count", 0);
        evidence.set("client_http_status_counts", mapper.valueToTree(statuses));
        evidence.put("source_event_conservation", true); evidence.put("client_attempt_status_conservation", true);
        evidence.put("client_server_status_conservation", "NOT_APPLICABLE_AUTH_EVENTS_HAVE_NO_HTTP_STATUS");
        evidence.put("configured_login_attempts_per_ip_per_minute", 5);
        evidence.put("configured_login_attempts_per_account_per_minute", 5);
        evidence.put("limiter_bypassed_or_reset", false); evidence.put("maximum_client_requests_per_second", 5);
        evidence.put("minimum_send_spacing_nanos", minimumSpacingNanos);
        evidence.put("coverage_session", "NO_DATA"); evidence.set("feature_sanity_counts", mapper.valueToTree(sanity));
        evidence.put("feature_generation", "IN_MEMORY_OPEN_WINDOW_SANITY_CHECK_ONLY");
        evidence.put("persisted_aggregation_or_window_closure", "NOT_RUN_NOT_FORCED");
        evidence.put("elapsed_window_closure_proven", false); evidence.put("timestamps_rewritten", false);
        evidence.put("model_training_or_activation", "NOT_RUN"); evidence.put("provider_or_aws_calls", "NOT_RUN");
        evidence.put("labels_present_in_event_records", false); evidence.put("payload_privacy_allowlist_verified", true);
        evidence.put("raw_private_value_exclusion_verified", true);
        evidence.put("reuse_constraint", "LATER_REPLAY_MUST_BE_DEMO_ONLY_SIMULATED_FROM_CONTROLLED_TRACES");
        evidence.put("directory_mode", "700"); evidence.put("file_mode", "600");

        String eventsString = eventText.toString();
        String scenariosString = pretty(mapper, scenarioRoot);
        String attemptsString = pretty(mapper, clientRoot);
        evidence.put("trace_events_sha256", ControlledTraceCaptureArtifacts.sha256(eventsString));
        evidence.put("scenarios_sha256", ControlledTraceCaptureArtifacts.sha256(scenariosString));
        evidence.put("client_http_attempts_sha256", ControlledTraceCaptureArtifacts.sha256(attemptsString));
        evidence.put("client_ledger_file", ATTEMPTS_FILE);
        evidence.put("client_ledger_sha256", ControlledTraceCaptureArtifacts.sha256(attemptsString));
        Map<String, String> files = new LinkedHashMap<>();
        files.put(EVENTS_FILE, eventsString); files.put(SCENARIOS_FILE, scenariosString);
        files.put(ATTEMPTS_FILE, attemptsString); files.put(EVIDENCE_FILE, pretty(mapper, evidence));
        Set<String> excluded = new HashSet<>(forbiddenPrivateValues);
        excluded.add(sourceAccount); captured.forEach(event -> excluded.add(event.getId()));
        require(excluded.stream().allMatch(value -> value != null && !value.isBlank()), "Private exclusion sentinels required");
        for (String content : files.values()) {
            require(!content.contains("/api/") && !content.contains("access_token") && !content.contains("Bearer "),
                    "Raw request or authentication content must never be exported");
            for (String privateValue : excluded) require(!content.contains(privateValue), "Private capture value detected");
        }
        for (var file : files.entrySet()) {
            Path target = output.resolve(file.getKey());
            try (var channel = Files.newByteChannel(target, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                ByteBuffer bytes = StandardCharsets.UTF_8.encode(file.getValue());
                while (bytes.hasRemaining()) channel.write(bytes);
            }
            require(Files.readString(target).equals(file.getValue())
                            && Files.getPosixFilePermissions(target).equals(PosixFilePermissions.fromString("rw-------")),
                    "Private artifact bytes and permissions must pass readback");
        }
    }

    /** Exercise unchanged schemas 1-4 with observed timestamps, without persisting or closing a window. */
    static Map<String, Double> verifyOpenWindowFeatureCounts(List<SiemSecurityEvent> owned) {
        var grouped = owned.stream().collect(Collectors.groupingBy(event -> windowStart(event.getEventTimestamp())));
        double failed = 0, peak = 0;
        for (var entry : grouped.entrySet()) {
            LocalDateTime asOf = entry.getKey();
            var snapshot = AccountBaselinePolicy.summarize(List.of(), asOf, ZoneOffset.UTC);
            var base = AccountBehaviorFeatures.fromEvents(entry.getValue(), snapshot.features(), ZoneOffset.UTC);
            var personal = AccountBehaviorFeatures.withPersonalFeatures(base, snapshot);
            var contextual = ContextualBehaviorFeatures.fromEvents(personal, snapshot, entry.getValue());
            var schema4 = SessionEndpointBehaviorFeatures.fromEvents(contextual,
                    AccountBaselinePolicy.observedRequests(List.of(), asOf), asOf, entry.getValue());
            require(schema4.featureSchemaVersion() == 4 && schema4.values().get(0) == 0
                            && schema4.values().get(4) == 0 && schema4.values().get(25) == 0
                            && schema4.values().get(31) == 0 && schema4.values().get(32) == 0
                            && schema4.values().get(33) == 0 && schema4.values().get(34) == 0,
                    "Target-associated AUTH failures must not fabricate HTTP or session coverage");
            failed += schema4.values().get(3); peak = Math.max(peak, schema4.values().get(22));
        }
        require(failed == owned.size(), "Existing failed-login features must count all verified target-associated failures");
        return Map.of("failed_login_count", failed, "failed_login_peak_60s", peak,
                "request_count", 0.0, "session_metadata_count", 0.0, "distinct_authenticated_session_count", 0.0);
    }

    private static LocalDateTime windowStart(LocalDateTime timestamp) {
        return timestamp.withMinute(timestamp.getMinute() / 15 * 15).withSecond(0).withNano(0);
    }

    private static String pretty(ObjectMapper mapper, ObjectNode node) throws Exception {
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node) + "\n";
    }

    private static void require(boolean condition, String safeMessage) {
        if (!condition) throw new IllegalArgumentException(safeMessage);
    }
}
