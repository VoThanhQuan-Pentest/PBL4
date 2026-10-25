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
import java.util.stream.Collectors;

/** Separate capture-v2 allowlist: actual password mutations, not a sensitive-action-abuse label. */
final class SensitiveActionControlledCaptureArtifacts {
    static final String EVENTS_FILE = "trace-events.ndjson";
    static final String SCENARIOS_FILE = "scenarios.json";
    static final String ATTEMPTS_FILE = "client-attempts.ndjson";
    static final String EVIDENCE_FILE = "capture-evidence.json";
    private static final Set<String> ATTEMPT_KINDS = Set.of("CSRF_READ", "CSRF_REFRESH", "LOGIN",
            "CURRENT_SESSION_REQUEST", "REVOKED_SESSION_ATTEMPT");

    record Scenario(String accountAlias, String scenarioId, String family, String expectedLabel,
                    String plannedCause) {
        Scenario {
            require(opaque(accountAlias, "account-") && opaque(scenarioId, "scenario-"), "Opaque scenario references required");
            require(("BENIGN_PASSWORD_CHANGE".equals(family) && "BENIGN".equals(expectedLabel)
                    && "OWNED_PASSWORD_MAINTENANCE".equals(plannedCause))
                    || ("CONTROLLED_PASSWORD_CHANGE_SEQUENCE".equals(family)
                    && "UNSCORED_CONTROLLED_SEQUENCE".equals(expectedLabel)
                    && "OWNED_REPEATED_CHANGE_SESSION_REVOCATION".equals(plannedCause)),
                    "Supported planned scenario required; password change alone is not abuse");
        }
    }

    record ClientAttempt(int sequence, String intendedAccountAlias, Instant attemptedAt,
                         String kind, String method, String routeGroup, int status) {
        ClientAttempt {
            require(sequence >= 0 && opaque(intendedAccountAlias, "account-") && attemptedAt != null,
                    "Valid client attempt reference required");
            require(ATTEMPT_KINDS.contains(kind) && Set.of("GET", "POST", "PUT").contains(method)
                    && Set.of("auth", "profile").contains(routeGroup) && status >= 100 && status <= 599,
                    "Bounded client attempt fields required");
            require(switch (kind) {
                case "CSRF_READ", "CSRF_REFRESH" -> "GET".equals(method) && "auth".equals(routeGroup) && status == 200;
                case "LOGIN" -> "POST".equals(method) && "auth".equals(routeGroup) && status == 200;
                case "REVOKED_SESSION_ATTEMPT" -> "GET".equals(method) && "profile".equals(routeGroup) && status == 401;
                default -> "profile".equals(routeGroup)
                        && (("GET".equals(method) && status == 200) || ("PUT".equals(method) && status == 204));
            }, "Client attempt kind must match actual request/response");
        }
    }

    private SensitiveActionControlledCaptureArtifacts() {}

    static Path createFreshPrivateDirectory(Path projectRoot, String requestedDirectory) throws Exception {
        require(requestedDirectory != null && !requestedDirectory.isBlank(), "Explicit fresh capture directory required");
        Path root = projectRoot.toAbsolutePath().normalize();
        require(Files.isRegularFile(root.resolve("backend/pom.xml"), LinkOption.NOFOLLOW_LINKS)
                && root.toRealPath().equals(root), "Non-symlinked project root required");
        Path observability = root.resolve("observability");
        require(Files.isDirectory(observability, LinkOption.NOFOLLOW_LINKS)
                && observability.toRealPath().equals(observability), "Non-symlinked observability directory required");
        Path runtime = observability.resolve("runtime");
        if (!Files.exists(runtime, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(runtime,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        require(Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) && runtime.toRealPath().equals(runtime),
                "Non-symlinked runtime directory required");
        Path requested = Path.of(requestedDirectory);
        require(requested.isAbsolute(), "Absolute capture directory required");
        Path output = requested.normalize();
        require(runtime.equals(output.getParent())
                && output.getFileName().toString().matches("[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
                && !Files.exists(output, LinkOption.NOFOLLOW_LINKS), "Fresh direct child of observability/runtime required");
        return Files.createDirectory(output,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    static void write(Path output, ObjectMapper mapper, List<SiemSecurityEvent> captured,
                      Map<String, String> accountAliases, List<Scenario> scenarios,
                      List<ClientAttempt> attempts, Instant startedAt, Instant finishedAt,
                      long minimumSpacingNanos, Set<String> forbiddenValues) throws Exception {
        require(Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(output)
                && Files.getPosixFilePermissions(output).equals(PosixFilePermissions.fromString("rwx------")),
                "Private capture directory mode 700 required");
        try (var existing = Files.list(output)) { require(existing.findAny().isEmpty(), "Empty fresh directory required"); }
        require(startedAt != null && finishedAt != null && !finishedAt.isBefore(startedAt)
                && Duration.between(startedAt, finishedAt).compareTo(Duration.ofSeconds(60)) <= 0,
                "Actual UTC workload within 60 seconds required");
        require(minimumSpacingNanos >= Duration.ofMillis(200).toNanos() && attempts.size() > 0 && attempts.size() <= 100,
                "Bounded workload at maximum 5 RPS required");
        Set<String> aliases = new HashSet<>(accountAliases.values());
        require(aliases.size() == accountAliases.size() && scenarios.size() == aliases.size()
                && scenarios.stream().map(Scenario::accountAlias).collect(Collectors.toSet()).equals(aliases)
                && scenarios.stream().map(Scenario::scenarioId).distinct().count() == scenarios.size(),
                "Exact unique scenario/account correspondence required");
        require(captured.stream().map(SiemSecurityEvent::getId).distinct().count() == captured.size(),
                "Duplicate source events are not allowed");

        List<ObjectNode> records = new ArrayList<>();
        Map<String, Long> types = new TreeMap<>();
        Map<Integer, Long> serverStatuses = new TreeMap<>();
        Map<String, Long> serverHttp = new TreeMap<>();
        Map<String, Long> serverLogins = new TreeMap<>();
        Map<String, Long> serverChanges = new TreeMap<>();
        Map<String, Long> accountEventCounts = new TreeMap<>();
        Map<String, Set<String>> sessions = new TreeMap<>();
        for (SiemSecurityEvent event : captured.stream().sorted(Comparator
                .comparing(SiemSecurityEvent::getEventTimestamp).thenComparing(SiemSecurityEvent::getId)).toList()) {
            String alias = accountAliases.get(event.getActorUserId());
            require(alias != null && (event.getTargetUserId() == null || event.getActorUserId().equals(event.getTargetUserId()))
                    && event.getDemoLabel() == null, "Only actual unlabelled owned actor events allowed");
            Instant timestamp = event.getEventTimestamp().toInstant(ZoneOffset.UTC);
            require(inCapture(timestamp, startedAt, finishedAt), "Actual unmodified UTC event timestamp required");
            ObjectNode row = mapper.createObjectNode();
            row.put("account_alias", alias); row.put("event_sequence", records.size());
            row.put("event_timestamp", timestamp.toString()); row.put("event_type", event.getEventType());
            row.put("action", event.getAction()); row.put("outcome", event.getOutcome());
            row.put("route_group", event.getRouteGroup());
            if ("DOMAIN_ACTION".equals(event.getEventType())) {
                require("PASSWORD_CHANGE".equals(event.getAction()) && "SUCCESS".equals(event.getOutcome())
                        && "account".equals(event.getRouteGroup()) && event.getSourceIp() == null
                        && event.getUserAgentFamily() == null, "Actual producer password-change fields required");
                noHttpOrSession(event);
                row.putNull("source_ip"); row.putNull("user_agent_family");
                serverChanges.merge(alias, 1L, Long::sum);
            } else {
                require("127.0.0.1".equals(event.getSourceIp())
                        && SecurityEventNormalizer.AGENT_FAMILIES.contains(event.getUserAgentFamily()),
                        "Actual loopback IP and bounded agent family required");
                row.put("source_ip", event.getSourceIp()); row.put("user_agent_family", event.getUserAgentFamily());
                if ("AUTH".equals(event.getEventType())) {
                    require("LOGIN".equals(event.getAction()) && "SUCCESS".equals(event.getOutcome())
                            && "auth".equals(event.getRouteGroup()), "Only actual successful login events allowed");
                    noHttpOrSession(event); serverLogins.merge(alias, 1L, Long::sum);
                } else {
                    require("HTTP_REQUEST".equals(event.getEventType()) && "API_REQUEST".equals(event.getAction())
                            && "SUCCESS".equals(event.getOutcome()) && "profile".equals(event.getRouteGroup())
                            && (("GET".equals(event.getHttpMethod()) && Integer.valueOf(200).equals(event.getHttpStatus()))
                            || ("PUT".equals(event.getHttpMethod()) && Integer.valueOf(204).equals(event.getHttpStatus()))),
                            "Actual bounded password/profile HTTP telemetry required");
                    require(Integer.valueOf(UebaSessionTelemetry.CONTRACT_VERSION).equals(event.getTelemetryContractVersion())
                            && EndpointCategory.fromStored(event.getEndpointCategory()).isPresent()
                            && ("GET".equals(event.getHttpMethod()) ? "PROFILE_READ" : "PROFILE_PASSWORD")
                                .equals(event.getEndpointCategory()), "Server endpoint metadata required");
                    require((event.getSessionPseudonym() == null) == (event.getSessionIssuedAt() == null),
                            "Session fields must be an actual paired value or both missing");
                    row.put("http_method", event.getHttpMethod()); row.put("http_status", event.getHttpStatus());
                    row.put("telemetry_contract_version", event.getTelemetryContractVersion());
                    row.put("endpoint_category", event.getEndpointCategory());
                    if (event.getSessionPseudonym() != null) {
                        require(event.getSessionPseudonym().matches("[a-f0-9]{64}")
                                && !event.getSessionIssuedAt().isAfter(event.getEventTimestamp()),
                                "Actual verified session metadata required");
                        row.put("session_pseudonym", event.getSessionPseudonym());
                        row.put("session_issued_at", event.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
                        sessions.computeIfAbsent(alias, ignored -> new HashSet<>()).add(event.getSessionPseudonym());
                    }
                    serverHttp.merge(httpKey(alias, event.getHttpMethod(), event.getHttpStatus()), 1L, Long::sum);
                    serverStatuses.merge(event.getHttpStatus(), 1L, Long::sum);
                }
            }
            types.merge(event.getEventType(), 1L, Long::sum); accountEventCounts.merge(alias, 1L, Long::sum);
            records.add(row);
        }

        List<ObjectNode> attemptRows = new ArrayList<>();
        Map<String, Long> kinds = new TreeMap<>();
        Map<String, Long> clientHttp = new TreeMap<>();
        Map<String, Long> clientLogins = new TreeMap<>();
        Map<String, Long> clientChanges = new TreeMap<>();
        Map<Integer, Long> clientStatuses = new TreeMap<>();
        for (ClientAttempt attempt : attempts) {
            require(attempt.sequence() == attemptRows.size() && aliases.contains(attempt.intendedAccountAlias())
                    && inCapture(attempt.attemptedAt(), startedAt, finishedAt), "Exact actual client attempt sequence required");
            ObjectNode row = mapper.createObjectNode();
            row.put("client_attempt_sequence", attempt.sequence()); row.put("intended_account_alias", attempt.intendedAccountAlias());
            row.put("attempted_at", attempt.attemptedAt().toString()); row.put("attempt_kind", attempt.kind());
            row.put("http_method", attempt.method()); row.put("route_group", attempt.routeGroup()); row.put("http_status", attempt.status());
            row.put("provenance", "CLIENT_OBSERVED_NOT_SERVER_ATTRIBUTION");
            attemptRows.add(row); kinds.merge(attempt.kind(), 1L, Long::sum); clientStatuses.merge(attempt.status(), 1L, Long::sum);
            if ("LOGIN".equals(attempt.kind())) clientLogins.merge(attempt.intendedAccountAlias(), 1L, Long::sum);
            if ("CURRENT_SESSION_REQUEST".equals(attempt.kind())) {
                clientHttp.merge(httpKey(attempt.intendedAccountAlias(), attempt.method(), attempt.status()), 1L, Long::sum);
                if ("PUT".equals(attempt.method())) clientChanges.merge(attempt.intendedAccountAlias(), 1L, Long::sum);
            }
        }
        require(clientLogins.values().stream().mapToLong(Long::longValue).sum() <= 5,
                "Production default five logins per IP/minute retained");
        require(serverHttp.equals(clientHttp) && serverLogins.equals(clientLogins) && serverChanges.equals(clientChanges)
                && accountEventCounts.keySet().equals(aliases), "Exact attributed HTTP/AUTH/DOMAIN conservation required");
        require(kinds.getOrDefault("REVOKED_SESSION_ATTEMPT", 0L) == clientChanges.values().stream().mapToLong(Long::longValue).sum(),
                "Each actual password change must preserve its next revoked-session attempt");
        require(kinds.getOrDefault("CSRF_READ", 0L).equals(kinds.getOrDefault("LOGIN", 0L)), "Exact login/CSRF workload required");
        require(kinds.getOrDefault("CSRF_REFRESH", 0L) == clientChanges.values().stream().mapToLong(Long::longValue).sum(),
                "Each actual password change must retain its real post-login CSRF refresh");

        String eventText = ndjson(mapper, records); String attemptText = ndjson(mapper, attemptRows);
        ObjectNode metadata = envelope(mapper); metadata.put("labels_separate_from_events", true);
        var scenarioRows = metadata.putArray("scenarios");
        for (Scenario scenario : scenarios) {
            ObjectNode row = scenarioRows.addObject(); row.put("account_alias", scenario.accountAlias());
            row.put("scenario_id", scenario.scenarioId()); row.put("family", scenario.family());
            row.put("expected_label", scenario.expectedLabel()); row.put("planned_cause", scenario.plannedCause());
            row.put("observed_event_count", accountEventCounts.get(scenario.accountAlias()));
            row.put("observed_session_count", sessions.getOrDefault(scenario.accountAlias(), Set.of()).size());
        }
        String scenarioText = pretty(mapper, metadata);
        ObjectNode evidence = envelope(mapper); evidence.put("passed", true);
        evidence.put("scope", "OWNED_RANDOM_PORT_BACKEND_TESTCONTAINERS_MYSQL_REDIS_ONLY");
        evidence.put("capture_started_at", startedAt.toString()); evidence.put("capture_finished_at", finishedAt.toString());
        evidence.put("capture_duration_millis", Duration.between(startedAt, finishedAt).toMillis());
        evidence.put("event_count", captured.size()); evidence.put("client_request_count", attempts.size());
        evidence.set("event_type_counts", mapper.valueToTree(types)); evidence.set("client_attempt_kind_counts", mapper.valueToTree(kinds));
        evidence.set("client_http_status_counts", mapper.valueToTree(clientStatuses));
        evidence.set("server_http_status_counts", mapper.valueToTree(serverStatuses));
        evidence.set("attributed_server_http_counts", mapper.valueToTree(serverHttp));
        evidence.set("matching_current_session_client_http_counts", mapper.valueToTree(clientHttp));
        evidence.put("attributed_http_auth_domain_conservation", true);
        evidence.put("source_event_conservation", true); evidence.put("labels_present_in_event_records", false);
        evidence.put("revoked_session_attempts_preserved_as_client_observations", true);
        evidence.put("revoked_attempt_server_account_attribution", "NOT_OBSERVED_NOT_FABRICATED");
        evidence.put("all_client_requests_equal_server_events", false);
        evidence.put("maximum_client_requests_per_second", 5); evidence.put("minimum_send_spacing_nanos", minimumSpacingNanos);
        evidence.put("maximum_login_attempts_per_ip_per_minute", 5); evidence.put("login_rate_limit_overridden", false);
        evidence.put("payload_privacy_allowlist_verified", true); evidence.put("raw_private_value_exclusion_verified", true);
        evidence.put("timestamps_rewritten", false); evidence.put("window_closure", "NOT_OBSERVED_NOT_FORCED");
        evidence.put("elapsed_window_closure_proven", false); evidence.put("feature_generation", "NOT_RUN_CAPTURE_ONLY");
        evidence.put("model_training_or_activation", "NOT_RUN"); evidence.put("provider_or_aws_calls", "NOT_RUN");
        evidence.put("sensitive_action_abuse_qualification", "NOT_ESTABLISHED_REQUIRES_VALID_ABUSE_PROTOCOL");
        evidence.put("qualification_readiness", "COLD_NOT_READY");
        evidence.put("trace_events_sha256", sha256(eventText)); evidence.put("scenarios_sha256", sha256(scenarioText));
        evidence.put("client_ledger_file", ATTEMPTS_FILE); evidence.put("client_ledger_sha256", sha256(attemptText));
        evidence.put("directory_mode", "700"); evidence.put("file_mode", "600");
        Map<String, String> files = new LinkedHashMap<>(); files.put(EVENTS_FILE, eventText); files.put(SCENARIOS_FILE, scenarioText);
        files.put(ATTEMPTS_FILE, attemptText); files.put(EVIDENCE_FILE, pretty(mapper, evidence));
        require(!forbiddenValues.isEmpty() && forbiddenValues.stream().allMatch(value -> value != null && !value.isBlank()),
                "Private exclusion sentinels required");
        for (String content : files.values()) {
            require(!content.contains("/api/") && !content.contains("access_token") && !content.contains("Bearer "),
                    "Raw HTTP/auth content must not be exported");
            for (String value : forbiddenValues) require(!content.contains(value), "Private fixture content must not be exported");
            for (String account : accountAliases.keySet()) require(!content.contains(account), "Direct account identifiers must not be exported");
        }
        for (var file : files.entrySet()) {
            Path target = output.resolve(file.getKey());
            try (var channel = Files.newByteChannel(target, Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                ByteBuffer bytes = StandardCharsets.UTF_8.encode(file.getValue()); while (bytes.hasRemaining()) channel.write(bytes);
            }
            require(Files.readString(target).equals(file.getValue())
                    && Files.getPosixFilePermissions(target).equals(PosixFilePermissions.fromString("rw-------")),
                    "Exact private file readback required");
        }
    }

    private static void noHttpOrSession(SiemSecurityEvent event) {
        require(event.getHttpMethod() == null && event.getHttpStatus() == null && event.getTelemetryContractVersion() == null
                && event.getEndpointCategory() == null && event.getSessionPseudonym() == null && event.getSessionIssuedAt() == null,
                "Producer has no HTTP/session data; it must not be invented");
    }
    private static ObjectNode envelope(ObjectMapper mapper) {
        ObjectNode node = mapper.createObjectNode(); node.put("capture_contract_version", 2);
        node.put("provenance", "CONTROLLED_OWNED_LOCAL_HTTP"); return node;
    }
    private static String ndjson(ObjectMapper mapper, List<ObjectNode> rows) throws Exception {
        StringBuilder text = new StringBuilder(); for (ObjectNode row : rows) text.append(mapper.writeValueAsString(row)).append('\n');
        return text.toString();
    }
    private static String pretty(ObjectMapper mapper, ObjectNode node) throws Exception {
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(node) + "\n";
    }
    private static boolean opaque(String value, String prefix) { return value != null && value.matches(prefix + "[a-f0-9]{32}"); }
    private static boolean inCapture(Instant timestamp, Instant start, Instant end) { return !timestamp.isBefore(start) && !timestamp.isAfter(end); }
    private static String httpKey(String alias, String method, int status) { return alias + ":" + method + ":" + status; }
    static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    }
    private static void require(boolean condition, String safeMessage) { if (!condition) throw new IllegalArgumentException(safeMessage); }
}
