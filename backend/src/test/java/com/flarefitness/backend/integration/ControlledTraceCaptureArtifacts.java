package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.service.siem.EndpointCategory;
import com.flarefitness.backend.service.siem.SecurityEventNormalizer;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Test-only, fail-closed allowlist writer. It never serializes a database entity. */
final class ControlledTraceCaptureArtifacts {
    static final String EVENTS_FILE = "trace-events.ndjson";
    static final String SCENARIOS_FILE = "scenarios.json";
    static final String EVIDENCE_FILE = "capture-evidence.json";
    private static final Set<String> SAFE_HTTP_METHODS = Set.of("GET");

    record Scenario(String accountAlias, String scenarioId, String family, String expectedLabel) {
        Scenario {
            require(accountAlias != null && accountAlias.matches("account-[a-f0-9]{32}"), "Opaque account alias required");
            require(scenarioId != null && scenarioId.matches("scenario-[a-f0-9]{32}"), "Opaque scenario ID required");
            require(Set.of("NORMAL_BROWSING", "NORMAL_POLLING", "BOUNDED_BENIGN_BURST", "OWNED_ENDPOINT_SCAN")
                    .contains(family), "Unknown controlled scenario family");
            require(Set.of("BENIGN", "OWNED_ENDPOINT_SCAN").contains(expectedLabel), "Unknown scenario label");
        }
    }

    record CaptureCounts(int attemptedHttpRequests, int successfulLogins, int totalClientRequests,
                         Map<Integer, Long> clientHttpStatusCounts, long minimumSendSpacingNanos) {}

    private ControlledTraceCaptureArtifacts() {}

    static Path createFreshPrivateDirectory(Path projectRoot, String requestedDirectory) throws Exception {
        require(requestedDirectory != null && !requestedDirectory.isBlank(), "Explicit fresh capture directory required");
        Path root = projectRoot.toAbsolutePath().normalize();
        require(Files.isRegularFile(root.resolve("backend/pom.xml"), LinkOption.NOFOLLOW_LINKS)
                && Files.isDirectory(root.resolve("observability"), LinkOption.NOFOLLOW_LINKS), "Project root required");
        require(root.toRealPath().equals(root), "Symlinked project root is not allowed");
        Path runtime = root.resolve("observability/runtime");
        require(root.resolve("observability").toRealPath().equals(root.resolve("observability")),
                "Symlinked observability directory is not allowed");
        if (!Files.exists(runtime, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(runtime, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        require(Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) && runtime.toRealPath().equals(runtime),
                "Runtime directory must not be a symlink");
        Path output = Path.of(requestedDirectory).toAbsolutePath().normalize();
        require(runtime.equals(output.getParent()), "Capture directory must be a direct child of observability/runtime");
        require(output.getFileName().toString().matches("[A-Za-z0-9][A-Za-z0-9._-]{0,95}"),
                "Invalid capture directory name");
        require(!Files.exists(output, LinkOption.NOFOLLOW_LINKS), "Capture directory must be fresh, never overwritten");
        return Files.createDirectory(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    static void write(Path output, ObjectMapper mapper, List<SiemSecurityEvent> captured,
                      Map<String, String> accountAliases, List<Scenario> scenarios,
                      Instant startedAt, Instant finishedAt, CaptureCounts counts,
                      Set<String> forbiddenPrivateValues) throws Exception {
        require(Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(output),
                "Private capture directory required");
        require(Files.getPosixFilePermissions(output).equals(PosixFilePermissions.fromString("rwx------")),
                "Capture directory mode must be 700");
        try (var existing = Files.list(output)) {
            require(existing.findAny().isEmpty(), "Capture writer requires an empty fresh directory");
        }
        require(!finishedAt.isBefore(startedAt) && Duration.between(startedAt, finishedAt).compareTo(Duration.ofSeconds(60)) <= 0,
                "Capture workload must finish within 60 seconds");
        require(counts.minimumSendSpacingNanos() >= Duration.ofMillis(200).toNanos(), "Maximum 5 RPS required");
        require(counts.attemptedHttpRequests() > 0 && counts.successfulLogins() > 0
                && counts.totalClientRequests() >= counts.attemptedHttpRequests() + counts.successfulLogins()
                && counts.totalClientRequests() <= 300, "Bounded conserved controlled workload required");
        require(scenarios.size() == accountAliases.size()
                && scenarios.stream().map(Scenario::scenarioId).distinct().count() == scenarios.size()
                && new HashSet<>(accountAliases.values()).size() == accountAliases.size()
                && scenarios.stream().map(Scenario::accountAlias).collect(java.util.stream.Collectors.toSet())
                    .equals(new HashSet<>(accountAliases.values())), "Exact scenario/account alias correspondence required");
        require(new HashSet<>(captured.stream().map(SiemSecurityEvent::getId).toList()).size() == captured.size(),
                "Duplicate source events are not allowed");
        List<SiemSecurityEvent> ordered = captured.stream().sorted(Comparator
                .comparing(SiemSecurityEvent::getEventTimestamp).thenComparing(SiemSecurityEvent::getId)).toList();
        List<ObjectNode> records = new ArrayList<>();
        Map<Integer, Long> serverStatuses = new TreeMap<>();
        Map<String, Long> types = new TreeMap<>();
        Map<String, Long> accounts = new TreeMap<>();
        Map<String, Set<String>> sessions = new TreeMap<>();
        int sequence = 0;
        for (SiemSecurityEvent event : ordered) {
            String alias = accountAliases.get(event.getActorUserId());
            require(alias != null && (event.getTargetUserId() == null
                    || event.getActorUserId().equals(event.getTargetUserId())) && event.getDemoLabel() == null,
                    "Only actual owned actor telemetry is allowed");
            Instant timestamp = event.getEventTimestamp().toInstant(ZoneOffset.UTC);
            require(!timestamp.isBefore(startedAt) && !timestamp.isAfter(finishedAt), "Actual UTC capture timestamp required");
            require("127.0.0.1".equals(event.getSourceIp()), "Only actual loopback source IP is allowed");
            require(SecurityEventNormalizer.AGENT_FAMILIES.contains(event.getUserAgentFamily()), "Bounded agent family required");
            ObjectNode record = mapper.createObjectNode();
            record.put("account_alias", alias); record.put("event_sequence", sequence++);
            record.put("event_timestamp", timestamp.toString()); record.put("event_type", event.getEventType());
            record.put("action", event.getAction()); record.put("outcome", event.getOutcome());
            record.put("source_ip", event.getSourceIp()); record.put("user_agent_family", event.getUserAgentFamily());
            if ("HTTP_REQUEST".equals(event.getEventType())) {
                require("API_REQUEST".equals(event.getAction()) && SAFE_HTTP_METHODS.contains(event.getHttpMethod())
                        && event.getHttpStatus() != null && event.getHttpStatus() >= 100 && event.getHttpStatus() <= 599,
                        "Valid actual HTTP telemetry required");
                require((event.getHttpStatus() >= 400 ? "FAILURE" : "SUCCESS").equals(event.getOutcome()),
                        "HTTP outcome/status mismatch");
                require(SecurityEventNormalizer.REQUEST_GROUPS.contains(event.getRouteGroup()), "Bounded route group required");
                require(Integer.valueOf(UebaSessionTelemetry.CONTRACT_VERSION).equals(event.getTelemetryContractVersion())
                        && EndpointCategory.fromStored(event.getEndpointCategory()).isPresent(), "Server endpoint contract required");
                require(event.getSessionPseudonym() != null && event.getSessionPseudonym().matches("[a-f0-9]{64}")
                        && event.getSessionIssuedAt() != null && !event.getSessionIssuedAt().isAfter(event.getEventTimestamp()),
                        "Verified server session telemetry required; never invented by the writer");
                record.put("route_group", event.getRouteGroup()); record.put("http_method", event.getHttpMethod());
                record.put("http_status", event.getHttpStatus());
                record.put("telemetry_contract_version", event.getTelemetryContractVersion());
                record.put("endpoint_category", event.getEndpointCategory());
                record.put("session_pseudonym", event.getSessionPseudonym());
                record.put("session_issued_at", event.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
                serverStatuses.merge(event.getHttpStatus(), 1L, Long::sum);
                sessions.computeIfAbsent(alias, ignored -> new HashSet<>()).add(event.getSessionPseudonym());
            } else {
                require("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction())
                        && "SUCCESS".equals(event.getOutcome()) && "auth".equals(event.getRouteGroup()),
                        "Only actual successful controlled login events are allowed");
                require(event.getSessionPseudonym() == null && event.getSessionIssuedAt() == null
                        && event.getHttpMethod() == null && event.getHttpStatus() == null, "No invented AUTH session/HTTP fields");
                record.put("route_group", "auth");
            }
            types.merge(event.getEventType(), 1L, Long::sum); accounts.merge(alias, 1L, Long::sum);
            records.add(record);
        }
        require(types.getOrDefault("HTTP_REQUEST", 0L) == counts.attemptedHttpRequests()
                && types.getOrDefault("AUTH", 0L) == counts.successfulLogins()
                && captured.size() == counts.attemptedHttpRequests() + counts.successfulLogins(),
                "Exact source event conservation required; no ambiguous cases may be dropped");
        require(serverStatuses.equals(new TreeMap<>(counts.clientHttpStatusCounts())), "Exact client/server status conservation required");
        require(accounts.keySet().equals(new HashSet<>(accountAliases.values())), "All controlled accounts must be captured");
        StringBuilder ndjson = new StringBuilder();
        for (ObjectNode record : records) ndjson.append(mapper.writeValueAsString(record)).append('\n');
        String eventText = ndjson.toString();
        ObjectNode scenarioRoot = mapper.createObjectNode();
        scenarioRoot.put("schema_version", 1); scenarioRoot.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        scenarioRoot.put("labels_separate_from_events", true);
        var scenarioArray = scenarioRoot.putArray("scenarios");
        for (Scenario scenario : scenarios) {
            ObjectNode node = scenarioArray.addObject();
            node.put("account_alias", scenario.accountAlias()); node.put("scenario_id", scenario.scenarioId());
            node.put("family", scenario.family()); node.put("expected_label", scenario.expectedLabel());
            node.put("observed_event_count", accounts.get(scenario.accountAlias()));
            node.put("observed_session_count", sessions.getOrDefault(scenario.accountAlias(), Set.of()).size());
        }
        String scenarioText = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(scenarioRoot) + "\n";
        ObjectNode evidence = mapper.createObjectNode();
        evidence.put("schema_version", 1); evidence.put("passed", true);
        evidence.put("scope", "OWNED_RANDOM_PORT_BACKEND_TESTCONTAINERS_MYSQL_REDIS_ONLY");
        evidence.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        evidence.put("capture_started_at", startedAt.toString()); evidence.put("capture_finished_at", finishedAt.toString());
        evidence.put("capture_duration_millis", Duration.between(startedAt, finishedAt).toMillis());
        evidence.put("event_count", captured.size()); evidence.put("http_request_count", counts.attemptedHttpRequests());
        evidence.put("successful_login_count", counts.successfulLogins()); evidence.put("client_request_count", counts.totalClientRequests());
        evidence.put("maximum_client_requests_per_second", 5); evidence.put("minimum_send_spacing_nanos", counts.minimumSendSpacingNanos());
        evidence.put("trace_events_sha256", sha256(eventText)); evidence.put("scenarios_sha256", sha256(scenarioText));
        evidence.set("client_http_status_counts", mapper.valueToTree(new TreeMap<>(counts.clientHttpStatusCounts())));
        evidence.set("server_http_status_counts", mapper.valueToTree(serverStatuses));
        evidence.set("event_type_counts", mapper.valueToTree(types));
        evidence.put("source_event_conservation", true); evidence.put("client_server_status_conservation", true);
        evidence.put("labels_present_in_event_records", false); evidence.put("payload_privacy_allowlist_verified", true);
        evidence.put("raw_private_value_exclusion_verified", true);
        evidence.put("timestamps_rewritten", false); evidence.put("elapsed_window_closure_proven", false);
        evidence.put("window_closure", "NOT_OBSERVED_NOT_FORCED"); evidence.put("feature_generation", "NOT_RUN_CAPTURE_ONLY");
        evidence.put("model_training_or_activation", "NOT_RUN"); evidence.put("provider_or_aws_calls", "NOT_RUN");
        evidence.put("reuse_constraint", "LATER_REPLAY_MUST_BE_DEMO_ONLY_SIMULATED_FROM_CONTROLLED_TRACES");
        evidence.put("directory_mode", "700"); evidence.put("file_mode", "600");
        String evidenceText = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(evidence) + "\n";
        Map<String, String> files = new LinkedHashMap<>();
        files.put(EVENTS_FILE, eventText); files.put(SCENARIOS_FILE, scenarioText); files.put(EVIDENCE_FILE, evidenceText);
        for (String content : files.values()) {
            require(!content.contains("/api/") && !content.contains("access_token") && !content.contains("Bearer "),
                    "Raw HTTP/auth content must not be exported");
            for (String forbidden : forbiddenPrivateValues) {
                require(forbidden != null && !forbidden.isBlank(), "Private exclusion sentinel required");
                require(!content.contains(forbidden), "Private fixture content must not be exported");
            }
            for (String sourceAccount : accountAliases.keySet()) {
                require(!content.contains(sourceAccount), "Source account identifiers must not be exported");
            }
        }
        for (var file : files.entrySet()) {
            Path target = output.resolve(file.getKey());
            writePrivateFile(target, file.getValue());
            require(Files.readString(target).equals(file.getValue())
                    && Files.getPosixFilePermissions(target).equals(PosixFilePermissions.fromString("rw-------")),
                    "Private capture file readback must match bytes and mode");
        }
    }

    private static void writePrivateFile(Path path, String content) throws Exception {
        try (var channel = Files.newByteChannel(path, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = StandardCharsets.UTF_8.encode(content);
            while (buffer.hasRemaining()) channel.write(buffer);
        }
    }

    static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    private static void require(boolean condition, String safeMessage) {
        if (!condition) throw new IllegalArgumentException(safeMessage);
    }
}
