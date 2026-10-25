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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** V2 private, test-only source artifacts. Intent is not inferred from a response status. */
final class ControlledOperationalCaptureArtifacts {
    static final String EVENTS_FILE = "trace-events.ndjson";
    static final String SCENARIOS_FILE = "scenarios.json";
    static final String CLIENT_LEDGER_FILE = "client-ledger.ndjson";
    static final String EVIDENCE_FILE = "capture-evidence.json";
    private static final Set<String> KINDS = Set.of("CSRF_READ", "LOGIN", "NORMAL_READ", "CONTROLLED_FAULT",
            "AFTER_FAULT_NORMAL_READ", "RESOURCE_PROBE");

    record Scenario(String accountAlias, String scenarioId, String family, String expectedLabel) {
        Scenario {
            require(accountAlias != null && accountAlias.matches("account-[a-f0-9]{32}"), "Opaque account alias required");
            require(scenarioId != null && scenarioId.matches("scenario-[a-f0-9]{32}"), "Opaque scenario ID required");
            require(("OPERATIONAL_FAULT".equals(family) && "CONTROLLED_OPERATIONAL_ANOMALY".equals(expectedLabel))
                    || ("OWNED_RESOURCE_PROBE".equals(family) && "OBSERVATIONAL_AMBIGUOUS".equals(expectedLabel)),
                    "Controlled operational or ambiguous owned resource scenario required");
        }
    }

    record ClientObservation(String accountAlias, Instant sentAt, String requestKind, String httpMethod,
                             int expectedStatus, int observedStatus) {
        ClientObservation {
            require(accountAlias != null && accountAlias.matches("account-[a-f0-9]{32}") && sentAt != null,
                    "Owned timestamped client observation required");
            require(KINDS.contains(requestKind) && ("LOGIN".equals(requestKind) ? "POST" : "GET").equals(httpMethod),
                    "Bounded client request kind/method required");
            require(expectedStatus == observedStatus && Set.of(200, 503).contains(observedStatus)
                    && ("CONTROLLED_FAULT".equals(requestKind) ? observedStatus == 503 : observedStatus == 200),
                    "Actual controlled client response must match the plan");
        }
        boolean capturedHttp() { return !Set.of("CSRF_READ", "LOGIN").contains(requestKind); }
    }

    private ControlledOperationalCaptureArtifacts() {}

    static Path createFreshPrivateDirectory(Path projectRoot, String requestedDirectory) throws Exception {
        return ControlledTraceCaptureArtifacts.createFreshPrivateDirectory(projectRoot, requestedDirectory);
    }

    static void write(Path output, ObjectMapper mapper, List<SiemSecurityEvent> captured,
                      Map<String, String> accountAliases, List<Scenario> scenarios, List<ClientObservation> ledger,
                      Instant startedAt, Instant finishedAt, long minimumSendSpacingNanos,
                      Set<String> forbiddenPrivateValues) throws Exception {
        require(Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(output)
                && Files.getPosixFilePermissions(output).equals(PosixFilePermissions.fromString("rwx------")),
                "Fresh private capture directory mode 700 required");
        try (var existing = Files.list(output)) { require(existing.findAny().isEmpty(), "Capture directory must be empty"); }
        require(!finishedAt.isBefore(startedAt)
                && Duration.between(startedAt, finishedAt).compareTo(Duration.ofSeconds(60)) <= 0,
                "Capture workload must finish within 60 seconds");
        require(minimumSendSpacingNanos >= Duration.ofMillis(200).toNanos(), "Maximum 5 RPS required");
        require(!forbiddenPrivateValues.isEmpty() && !accountAliases.isEmpty() && ledger.size() <= 60,
                "Bounded owned workload and explicit privacy exclusions required");
        require(scenarios.size() == accountAliases.size()
                && scenarios.stream().map(Scenario::scenarioId).distinct().count() == scenarios.size()
                && new HashSet<>(accountAliases.values()).size() == accountAliases.size()
                && scenarios.stream().map(Scenario::accountAlias).collect(java.util.stream.Collectors.toSet())
                    .equals(new HashSet<>(accountAliases.values())), "Exact scenario/owned alias correspondence required");
        require(scenarios.stream().filter(scenario -> "OPERATIONAL_FAULT".equals(scenario.family())).count() == 1
                && scenarios.stream().filter(scenario -> "OWNED_RESOURCE_PROBE".equals(scenario.family())).count() <= 1,
                "Exactly one operational scenario and at most one ambiguous resource scenario required");
        require(new HashSet<>(captured.stream().map(SiemSecurityEvent::getId).toList()).size() == captured.size()
                && captured.stream().allMatch(event -> event.getId() != null), "Unique real source event IDs required");

        Map<String, String> families = new LinkedHashMap<>();
        scenarios.forEach(scenario -> families.put(scenario.accountAlias(), scenario.family()));
        Map<String, Map<Integer, Long>> clientByAccount = new TreeMap<>();
        Map<String, Long> clientLogins = new TreeMap<>();
        Map<String, Long> csrfReads = new TreeMap<>();
        Map<String, Long> planCounts = new TreeMap<>();
        StringBuilder clientText = new StringBuilder();
        Instant previous = null;
        int clientSequence = 0;
        for (ClientObservation observation : ledger) {
            require(families.containsKey(observation.accountAlias()) && !observation.sentAt().isBefore(startedAt)
                    && !observation.sentAt().isAfter(finishedAt)
                    && (previous == null || !observation.sentAt().isBefore(previous)), "Ordered actual owned client UTC required");
            previous = observation.sentAt();
            String family = families.get(observation.accountAlias());
            require("OPERATIONAL_FAULT".equals(family) ? !"RESOURCE_PROBE".equals(observation.requestKind())
                    : Set.of("CSRF_READ", "LOGIN", "RESOURCE_PROBE").contains(observation.requestKind()),
                    "Client request plan must remain within its separate scenario");
            planCounts.merge(observation.requestKind(), 1L, Long::sum);
            if (observation.capturedHttp()) {
                clientByAccount.computeIfAbsent(observation.accountAlias(), ignored -> new TreeMap<>())
                        .merge(observation.observedStatus(), 1L, Long::sum);
            } else if ("LOGIN".equals(observation.requestKind())) {
                clientLogins.merge(observation.accountAlias(), 1L, Long::sum);
            } else csrfReads.merge(observation.accountAlias(), 1L, Long::sum);
            ObjectNode node = mapper.createObjectNode();
            node.put("client_sequence", clientSequence++); node.put("account_alias", observation.accountAlias());
            node.put("sent_at", observation.sentAt().toString()); node.put("request_kind", observation.requestKind());
            node.put("http_method", observation.httpMethod()); node.put("expected_status", observation.expectedStatus());
            node.put("observed_status", observation.observedStatus());
            clientText.append(mapper.writeValueAsString(node)).append('\n');
        }
        require(clientLogins.keySet().equals(families.keySet()) && csrfReads.equals(clientLogins)
                && clientLogins.values().stream().allMatch(count -> count == 1L), "One real CSRF/login exchange per owned account required");
        require(planCounts.getOrDefault("NORMAL_READ", 0L) == 5 && planCounts.getOrDefault("CONTROLLED_FAULT", 0L) == 10
                && planCounts.getOrDefault("AFTER_FAULT_NORMAL_READ", 0L) == 1
                && planCounts.getOrDefault("RESOURCE_PROBE", 0L) == (families.containsValue("OWNED_RESOURCE_PROBE") ? 20 : 0),
                "Conserve the exact bounded normal/fault/recovery/resource plans");
        List<ClientObservation> faultPlan = ledger.stream().filter(observation -> "OPERATIONAL_FAULT"
                .equals(families.get(observation.accountAlias())) && observation.capturedHttp()).toList();
        require(faultPlan.size() == 16 && faultPlan.subList(0, 5).stream().allMatch(item -> "NORMAL_READ".equals(item.requestKind()))
                && faultPlan.subList(5, 15).stream().allMatch(item -> "CONTROLLED_FAULT".equals(item.requestKind()))
                && "AFTER_FAULT_NORMAL_READ".equals(faultPlan.get(15).requestKind()), "Normal/fault/recovery order required");

        Map<String, Map<Integer, Long>> serverByAccount = new TreeMap<>();
        Map<String, Long> serverLogins = new TreeMap<>();
        Map<String, Set<String>> sessions = new TreeMap<>();
        Map<String, Long> accountCounts = new TreeMap<>();
        Map<String, Long> eventTypeCounts = new TreeMap<>();
        StringBuilder eventText = new StringBuilder();
        int sequence = 0;
        for (SiemSecurityEvent event : captured.stream().sorted(Comparator
                .comparing(SiemSecurityEvent::getEventTimestamp).thenComparing(SiemSecurityEvent::getId)).toList()) {
            String alias = accountAliases.get(event.getActorUserId());
            require(alias != null && (event.getTargetUserId() == null || event.getActorUserId().equals(event.getTargetUserId()))
                    && event.getDemoLabel() == null, "Only actual unlabelled owned actor telemetry allowed");
            Instant timestamp = event.getEventTimestamp().toInstant(ZoneOffset.UTC);
            require(!timestamp.isBefore(startedAt) && !timestamp.isAfter(finishedAt), "Actual UTC timestamp required");
            require("127.0.0.1".equals(event.getSourceIp()) && SecurityEventNormalizer.AGENT_FAMILIES.contains(event.getUserAgentFamily()),
                    "Actual loopback source and bounded agent required");
            ObjectNode node = mapper.createObjectNode();
            node.put("account_alias", alias); node.put("event_sequence", sequence++); node.put("event_timestamp", timestamp.toString());
            node.put("event_type", event.getEventType()); node.put("action", event.getAction()); node.put("outcome", event.getOutcome());
            node.put("source_ip", event.getSourceIp()); node.put("user_agent_family", event.getUserAgentFamily());
            if ("HTTP_REQUEST".equals(event.getEventType())) {
                require("API_REQUEST".equals(event.getAction()) && "GET".equals(event.getHttpMethod())
                        && Set.of(200, 503).contains(event.getHttpStatus())
                        && (event.getHttpStatus() >= 400 ? "FAILURE" : "SUCCESS").equals(event.getOutcome()),
                        "Actual controlled GET status/outcome required");
                require(SecurityEventNormalizer.REQUEST_GROUPS.contains(event.getRouteGroup())
                        && Integer.valueOf(UebaSessionTelemetry.CONTRACT_VERSION).equals(event.getTelemetryContractVersion())
                        && EndpointCategory.fromStored(event.getEndpointCategory()).filter(EndpointCategory::isMatched).isPresent(),
                        "Server-resolved endpoint contract 3 required");
                require(event.getSessionPseudonym() != null && event.getSessionPseudonym().matches("[a-f0-9]{64}")
                        && event.getSessionIssuedAt() != null && !event.getSessionIssuedAt().isAfter(event.getEventTimestamp()),
                        "Verified actual server session required; never synthesized");
                if (event.getHttpStatus() == 503) require("OPERATIONAL_FAULT".equals(families.get(alias))
                        && "other_api".equals(event.getRouteGroup()) && "OTHER_MATCHED".equals(event.getEndpointCategory()),
                        "Fault status must originate from the resolved test-only controller");
                node.put("route_group", event.getRouteGroup()); node.put("http_method", event.getHttpMethod());
                node.put("http_status", event.getHttpStatus()); node.put("telemetry_contract_version", event.getTelemetryContractVersion());
                node.put("endpoint_category", event.getEndpointCategory()); node.put("session_pseudonym", event.getSessionPseudonym());
                node.put("session_issued_at", event.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
                serverByAccount.computeIfAbsent(alias, ignored -> new TreeMap<>()).merge(event.getHttpStatus(), 1L, Long::sum);
                sessions.computeIfAbsent(alias, ignored -> new HashSet<>()).add(event.getSessionPseudonym());
            } else {
                require("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction()) && "SUCCESS".equals(event.getOutcome())
                        && "auth".equals(event.getRouteGroup()) && event.getSessionPseudonym() == null && event.getSessionIssuedAt() == null
                        && event.getHttpMethod() == null && event.getHttpStatus() == null, "Real successful login without invented fields required");
                node.put("route_group", "auth"); serverLogins.merge(alias, 1L, Long::sum);
            }
            accountCounts.merge(alias, 1L, Long::sum); eventText.append(mapper.writeValueAsString(node)).append('\n');
            eventTypeCounts.merge(event.getEventType(), 1L, Long::sum);
        }
        require(serverByAccount.equals(clientByAccount) && serverLogins.equals(clientLogins)
                && accountCounts.keySet().equals(families.keySet()) && sessions.values().stream().allMatch(values -> values.size() == 1),
                "Exact per-account client/server source conservation required; no cases dropped");

        ObjectNode scenarioRoot = mapper.createObjectNode();
        scenarioRoot.put("schema_version", 2); scenarioRoot.put("capture_contract_version", 2);
        scenarioRoot.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        scenarioRoot.put("labels_separate_from_events", true);
        var scenarioArray = scenarioRoot.putArray("scenarios");
        for (Scenario scenario : scenarios) {
            ObjectNode node = scenarioArray.addObject(); node.put("account_alias", scenario.accountAlias());
            node.put("scenario_id", scenario.scenarioId()); node.put("family", scenario.family()); node.put("expected_label", scenario.expectedLabel());
            node.put("observed_event_count", accountCounts.get(scenario.accountAlias()));
            node.put("observed_session_count", sessions.get(scenario.accountAlias()).size());
            node.put("malicious_caller_asserted", false); node.put("attack_confirmation", false);
            if ("OPERATIONAL_FAULT".equals(scenario.family())) node.put("interpretation", "CONTROLLED_OPERATIONAL_ANOMALY_ONLY");
            else {
                node.put("interpretation", "AMBIGUOUS_BENIGN_EQUIVALENT_RESOURCE_READS");
                node.put("dos_or_disruption_demonstrated", false);
            }
        }
        String scenariosText = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(scenarioRoot) + '\n';
        ObjectNode evidence = mapper.createObjectNode();
        evidence.put("schema_version", 2); evidence.put("capture_contract_version", 2); evidence.put("passed", true);
        evidence.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP");
        evidence.put("scope", "OWNED_RANDOM_PORT_BACKEND_TESTCONTAINERS_MYSQL_REDIS_ONLY");
        evidence.put("capture_started_at", startedAt.toString()); evidence.put("capture_finished_at", finishedAt.toString());
        evidence.put("capture_duration_millis", Duration.between(startedAt, finishedAt).toMillis());
        evidence.put("event_count", captured.size()); evidence.put("http_request_count", ledger.stream().filter(ClientObservation::capturedHttp).count());
        evidence.put("successful_login_count", clientLogins.size()); evidence.put("client_request_count", ledger.size());
        evidence.put("maximum_client_requests_per_second", 5); evidence.put("minimum_send_spacing_nanos", minimumSendSpacingNanos);
        evidence.put("actual_controlled_503_count", 10); evidence.put("source_event_conservation", true);
        evidence.put("client_server_status_conservation", true); evidence.put("normal_fault_recovery_order_conserved", true);
        Map<Integer, Long> statusCounts = new TreeMap<>();
        serverByAccount.values().forEach(counts -> counts.forEach((status, count) -> statusCounts.merge(status, count, Long::sum)));
        evidence.set("client_http_status_counts", mapper.valueToTree(statusCounts)); evidence.set("server_http_status_counts", mapper.valueToTree(statusCounts));
        evidence.set("client_plan_counts", mapper.valueToTree(planCounts));
        evidence.set("event_type_counts", mapper.valueToTree(eventTypeCounts));
        evidence.put("trace_events_sha256", ControlledTraceCaptureArtifacts.sha256(eventText.toString()));
        evidence.put("scenarios_sha256", ControlledTraceCaptureArtifacts.sha256(scenariosText));
        evidence.put("client_ledger_sha256", ControlledTraceCaptureArtifacts.sha256(clientText.toString()));
        evidence.put("client_ledger_file", CLIENT_LEDGER_FILE);
        evidence.put("payload_privacy_allowlist_verified", true); evidence.put("raw_private_value_exclusion_verified", true);
        evidence.put("labels_present_in_event_records", false); evidence.put("timestamps_rewritten", false);
        evidence.put("malicious_caller_asserted", false); evidence.put("attack_confirmation", false);
        evidence.put("dos_or_disruption_demonstrated", false); evidence.put("independent_accuracy_dataset", false);
        evidence.put("actual_5xx_proof", "CONTROLLED_OPERATIONAL_ANOMALY_ONLY");
        evidence.put("resource_probe_interpretation", "AMBIGUOUS_BENIGN_EQUIVALENT_NO_DOS_OR_DISRUPTION");
        evidence.put("elapsed_window_closure_proven", false); evidence.put("window_closure", "NOT_OBSERVED_NOT_FORCED");
        evidence.put("feature_generation", "NOT_RUN_CAPTURE_ONLY"); evidence.put("model_training_or_activation", "NOT_RUN");
        evidence.put("provider_or_aws_calls", "NOT_RUN");
        evidence.put("reuse_constraint", "LATER_REPLAY_MUST_BE_DEMO_ONLY_SIMULATED_FROM_CONTROLLED_TRACES");
        evidence.put("directory_mode", "700"); evidence.put("file_mode", "600");
        Map<String, String> files = new LinkedHashMap<>();
        files.put(EVENTS_FILE, eventText.toString()); files.put(SCENARIOS_FILE, scenariosText);
        files.put(CLIENT_LEDGER_FILE, clientText.toString());
        files.put(EVIDENCE_FILE, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(evidence) + '\n');
        for (String content : files.values()) {
            require(!content.contains("/api/") && !content.contains("access_token") && !content.contains("Bearer "), "No raw HTTP/auth export allowed");
            for (String forbidden : forbiddenPrivateValues) require(forbidden != null && !forbidden.isBlank() && !content.contains(forbidden),
                    "Private fixture content must not be exported");
            for (String actor : accountAliases.keySet()) require(actor != null && !actor.isBlank() && !content.contains(actor),
                    "Source account identifiers must not be exported");
        }
        for (var file : files.entrySet()) {
            Path target = output.resolve(file.getKey());
            try (var channel = Files.newByteChannel(target, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                ByteBuffer buffer = StandardCharsets.UTF_8.encode(file.getValue());
                while (buffer.hasRemaining()) channel.write(buffer);
            }
            require(Files.readString(target).equals(file.getValue())
                    && Files.getPosixFilePermissions(target).equals(PosixFilePermissions.fromString("rw-------")), "Private file readback required");
        }
    }

    private static void require(boolean condition, String safeMessage) {
        if (!condition) throw new IllegalArgumentException(safeMessage);
    }
}
