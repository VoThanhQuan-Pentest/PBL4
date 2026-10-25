package com.flarefitness.backend.ops;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.service.siem.AccountBaselinePolicy;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.ContextualBehaviorFeatures;
import com.flarefitness.backend.service.siem.AccountRiskEngine;
import com.flarefitness.backend.service.siem.SecurityEventNormalizer;
import com.flarefitness.backend.service.siem.EndpointCategory;
import com.flarefitness.backend.service.siem.SessionEndpointBehaviorFeatures;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Offline DEMO_ONLY NDJSON events -> the exact backend's past-only feature snapshots. No DB/network. */
public final class UebaFeatureExport {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");
    private static final int MAX_LINE_BYTES = 2 * 1024 * 1024;
    private static final Set<String> FRAME_FIELDS = Set.of("frame_id", "account_id", "day", "cohort",
            "window_start", "demo_label", "family", "events", "telemetry_contract_version");
    private static final Set<String> EVENT_FIELDS = Set.of("event_timestamp", "event_type", "action", "outcome",
            "http_status", "route_group", "source_ip", "user_agent_family", "request_path", "user_agent", "http_method");
    private static final Set<String> SESSION_ENDPOINT_EVENT_FIELDS = java.util.stream.Stream.concat(EVENT_FIELDS.stream(),
            Set.of("endpoint_category", "session_pseudonym", "session_issued_at").stream()).collect(java.util.stream.Collectors.toUnmodifiableSet());
    private static final Set<String> FAMILIES = Set.of("normal", "request_burst", "endpoint_scan",
            "auth_failure_burst", "sensitive_action_burst", "http_error_burst");

    private UebaFeatureExport() { }

    public static void main(String[] args) {
        if ((args.length != 1 && args.length != 2) || !"--demo-only".equals(args[0])
                || args.length == 2 && !Set.of("--schema3", "--schema4").contains(args[1])) {
            System.err.println("Usage: UebaFeatureExport --demo-only [--schema3|--schema4] < events.ndjson > features.ndjson");
            System.exit(2);
        }
        try {
            History history = new History();
            BufferedInputStream input = new BufferedInputStream(System.in);
            int frames = 0;
            String line;
            while ((line = readLine(input)) != null) {
                if (++frames > 200_000) throw new IllegalArgumentException("Frame bound exceeded");
                int schema = args.length == 1 ? 2 : "--schema4".equals(args[1]) ? 4 : 3;
                System.out.println(JSON.writeValueAsString(transform(JSON.readTree(line), history, schema)));
                if (frames % 5000 == 0) System.err.println("DEMO_ONLY feature frames exported: " + frames);
            }
            if (frames == 0) throw new IllegalArgumentException("Empty dataset");
            System.err.println("DEMO_ONLY feature export completed: " + frames);
        } catch (Exception failure) {
            // No raw frames/identities/bodies or environment values in diagnostics.
            System.err.println("DEMO_ONLY feature export refused/failed: " + failure.getClass().getSimpleName());
            System.exit(2);
        }
    }

    static Map<String, Object> transform(JsonNode frame, History history) {
        return transform(frame, history, 2);
    }

    static Map<String, Object> transform(JsonNode frame, History history, int featureSchema) {
        if (!Set.of(2, 3, 4).contains(featureSchema)) throw new IllegalArgumentException("Unsupported exported feature schema.");
        allowFields(frame, FRAME_FIELDS);
        String id = boundedText(frame, "frame_id", 128);
        String account = boundedText(frame, "account_id", 64);
        if (!id.matches("[a-z0-9_-]{8,128}") || !account.matches("[a-z0-9_-]{8,64}")) {
            throw new IllegalArgumentException("Invalid pseudonymous dataset identity");
        }
        int telemetry = frame.path("telemetry_contract_version").asInt(1);
        if (frame.has("telemetry_contract_version") && !frame.path("telemetry_contract_version").isIntegralNumber()
                || !Set.of(1, 2, 3).contains(telemetry) || (featureSchema == 4) != (telemetry == 3)) {
            throw new IllegalArgumentException("Unknown telemetry normalization contract");
        }
        int day = frame.path("day").asInt(-1);
        // The raw-v2 experiment needs >14-day gaps between fit/calibration/
        // validation/holdout. This expands metadata only, not retained history,
        // per-process frames, account count, input bytes or event bounds.
        if (day < 1 || day > (telemetry >= 2 ? 110 : 70)) throw new IllegalArgumentException("Invalid dataset day");
        String cohort = boundedText(frame, "cohort", 16);
        if (!Set.of("DEVELOPMENT", "UNSEEN", "COLD", "DRIFT").contains(cohort)) {
            throw new IllegalArgumentException("Invalid dataset cohort");
        }
        String label = boundedText(frame, "demo_label", 16);
        String family = boundedText(frame, "family", 32);
        if (!Set.of("NORMAL", "ABNORMAL").contains(label) || !FAMILIES.contains(family)
                || "NORMAL".equals(label) != "normal".equals(family)) {
            throw new IllegalArgumentException("Invalid ground-truth label/family");
        }
        LocalDateTime start = timestamp(frame, "window_start");
        if (start.getMinute() % 15 != 0 || start.getSecond() != 0 || start.getNano() != 0) {
            throw new IllegalArgumentException("Window must align to a quarter hour");
        }
        JsonNode nodes = frame.path("events");
        if (!nodes.isArray() || nodes.isEmpty() || nodes.size() > 4096) {
            throw new IllegalArgumentException("Invalid event count");
        }
        List<SiemSecurityEvent> events = new ArrayList<>();
        for (JsonNode node : nodes) {
            allowFields(node, telemetry == 3 ? SESSION_ENDPOINT_EVENT_FIELDS : EVENT_FIELDS);
            SiemSecurityEvent event = new SiemSecurityEvent();
            event.setEventTimestamp(timestamp(node, "event_timestamp"));
            if (event.getEventTimestamp().isBefore(start) || !event.getEventTimestamp().isBefore(start.plusMinutes(15))) {
                throw new IllegalArgumentException("Event falls outside its window");
            }
            event.setEventType(boundedText(node, "event_type", 32));
            event.setAction(boundedText(node, "action", 32));
            event.setOutcome(boundedText(node, "outcome", 16));
            if (!Set.of("HTTP_REQUEST", "AUTH", "DOMAIN_ACTION").contains(event.getEventType())
                    || !Set.of("SUCCESS", "FAILURE").contains(event.getOutcome())) {
                throw new IllegalArgumentException("Invalid event type/outcome");
            }
            if (node.hasNonNull("http_status")) {
                if (!node.path("http_status").isIntegralNumber()) throw new IllegalArgumentException("Invalid HTTP status");
                int status = node.path("http_status").asInt();
                if (status < 100 || status > 599) throw new IllegalArgumentException("Invalid HTTP status");
                event.setHttpStatus(status);
            }
            event.setSourceIp(optionalText(node, "source_ip", 64));
            if (telemetry == 3 && (node.has("route_group") || node.has("user_agent_family"))) {
                // Sanitized operator-owned server traces, not a client claim of
                // authentication. This entire CLI remains offline DEMO_ONLY.
                if (node.has("request_path") || node.has("user_agent")) {
                    throw new IllegalArgumentException("Raw and normalized trace representations cannot be mixed.");
                }
                String group = boundedText(node, "route_group", 64);
                String agent = optionalText(node, "user_agent_family", 32);
                if (agent != null && !SecurityEventNormalizer.AGENT_FAMILIES.contains(agent)) {
                    throw new IllegalArgumentException("Unknown normalized agent family.");
                }
                if ("HTTP_REQUEST".equals(event.getEventType())) {
                    if (!SecurityEventNormalizer.REQUEST_GROUPS.contains(group)) throw new IllegalArgumentException("Unknown normalized route group.");
                    event.setHttpMethod(boundedText(node, "http_method", 8));
                    applySessionEndpointMetadata(event, node, account);
                } else if (!group.equals("AUTH".equals(event.getEventType()) ? "auth" : "account")) {
                    throw new IllegalArgumentException("Normalized group differs from event type.");
                }
                event.setRouteGroup(group); event.setUserAgentFamily(agent);
                if ("DOMAIN_ACTION".equals(event.getEventType())) {
                    event.setSourceIp(null); event.setUserAgentFamily(null);
                }
            } else if (telemetry >= 2) {
                if (node.has("route_group") || node.has("user_agent_family")) {
                    throw new IllegalArgumentException("Strict raw events cannot supply invented normalized groups/agents");
                }
                if ("HTTP_REQUEST".equals(event.getEventType())) {
                    String group = SecurityEventNormalizer.routeGroup(boundedText(node, "request_path", 2048));
                    if (group == null) continue; // Match the live capture exclusions exactly.
                    event.setRouteGroup(group);
                    event.setHttpMethod(boundedText(node, "http_method", 8));
                    event.setUserAgentFamily(SecurityEventNormalizer.userAgentFamily(optionalText(node, "user_agent", 2048)));
                    if (telemetry == 3) {
                        applySessionEndpointMetadata(event, node, account);
                    }
                } else if ("AUTH".equals(event.getEventType())) {
                    event.setRouteGroup("auth");
                    event.setUserAgentFamily(SecurityEventNormalizer.userAgentFamily(optionalText(node, "user_agent", 2048)));
                } else {
                    event.setRouteGroup("account");
                    event.setSourceIp(null); event.setUserAgentFamily(null);
                }
            } else {
                event.setRouteGroup(optionalText(node, "route_group", 64));
                event.setUserAgentFamily(optionalText(node, "user_agent_family", 32));
            }
            events.add(event);
        }
        if (events.isEmpty()) throw new IllegalArgumentException("Window has no account-observable telemetry");
        List<SiemAccountBehaviorWindow> previous = history.before(account, start);
        var snapshot = AccountBaselinePolicy.summarize(previous, start, ZONE);
        var raw = AccountBehaviorFeatures.fromEvents(events, snapshot.features(), ZONE);
        var personal = AccountBehaviorFeatures.withPersonalFeatures(raw, snapshot);
        var contextual = featureSchema >= 3 ? ContextualBehaviorFeatures.fromEvents(personal, snapshot, events) : null;
        var exported = featureSchema == 4 ? SessionEndpointBehaviorFeatures.fromEvents(contextual,
                AccountBaselinePolicy.observedRequests(previous, start), start, events) : featureSchema == 3 ? contextual : personal;
        var rule = AccountRiskEngine.assess(raw, null, snapshot.features().established());
        var stored = new SiemAccountBehaviorWindow();
        stored.setId(id);
        stored.setAccountId(account);
        stored.setWindowStart(start);
        stored.setWindowEnd(start.plusMinutes(15));
        String ip = events.stream().map(SiemSecurityEvent::getSourceIp).filter(value -> value != null)
                .reduce((old, current) -> current).orElse(null);
        String ua = events.stream().map(SiemSecurityEvent::getUserAgentFamily).filter(value -> value != null)
                .reduce((old, current) -> current).orElse(null);
        // Ground truth stays in the manifest/output. Never feed labels into the
        // baseline builder: simulate an unlabelled stream using raw evidence/rules only.
        stored.replaceFeatures(raw, events.size(), snapshot.features().established(), ip, ua, "REAL", start.plusMinutes(15));
        stored.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment(null, null,
                rule.riskScore(), String.join("; ", rule.reasons())), start.plusMinutes(15));
        previous.add(stored);
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("frame_id", id);
        output.put("account_id", account);
        output.put("day", day);
        output.put("cohort", cohort);
        output.put("window_start", start.toInstant(ZoneOffset.UTC).toString());
        output.put("label", "ABNORMAL".equals(label) ? 1 : 0);
        output.put("family", family);
        output.put("baseline_established", snapshot.features().established());
        output.put("trusted_window_count", snapshot.trustedWindows());
        output.put("feature_schema_version", featureSchema);
        output.put("telemetry_contract_version", telemetry);
        output.put("feature_names", AccountBehaviorFeatures.names(featureSchema));
        output.put("features", exported.values());
        output.put("rule_only_risk", rule.riskScore());
        output.put("rule_only_incident", rule.createIncident());
        output.put("data_provenance", "DEMO_ONLY");
        if (featureSchema == 4) output.put("telemetry_provenance", "OPERATOR_SANITIZED_OR_SIMULATED_CONTROLLED_TELEMETRY");
        return output;
    }

    private static void applySessionEndpointMetadata(SiemSecurityEvent event, JsonNode node, String account) {
        event.setTelemetryContractVersion(3); event.setActorUserId(account);
        String endpoint = optionalText(node, "endpoint_category", 64);
        if (endpoint != null) EndpointCategory.valueOf(endpoint);
        event.setEndpointCategory(endpoint);
        String session = optionalText(node, "session_pseudonym", 64);
        if ((session != null) != node.hasNonNull("session_issued_at")
                || session != null && !session.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid sanitized session telemetry.");
        event.setSessionPseudonym(session);
        event.setSessionIssuedAt(session == null ? null : timestamp(node, "session_issued_at"));
        if (event.getSessionIssuedAt() != null && event.getSessionIssuedAt().isAfter(event.getEventTimestamp())) {
            throw new IllegalArgumentException("Session issuance cannot occur after a captured request.");
        }
    }

    static final class History {
        private final Map<String, List<SiemAccountBehaviorWindow>> windows = new HashMap<>();
        private final Map<String, LocalDateTime> last = new HashMap<>();
        List<SiemAccountBehaviorWindow> before(String account, LocalDateTime start) {
            if (last.containsKey(account) && !last.get(account).isBefore(start)) {
                throw new IllegalArgumentException("Duplicate/out-of-order account window");
            }
            if (!windows.containsKey(account) && windows.size() >= 500) throw new IllegalArgumentException("Account bound exceeded");
            last.put(account, start);
            List<SiemAccountBehaviorWindow> result = windows.computeIfAbsent(account, ignored -> new ArrayList<>());
            result.removeIf(window -> window.getWindowStart().isBefore(start.minusDays(14)));
            return result;
        }
    }

    private static LocalDateTime timestamp(JsonNode object, String field) {
        return LocalDateTime.ofInstant(Instant.parse(boundedText(object, field, 40)), ZoneOffset.UTC);
    }
    private static String optionalText(JsonNode object, String field, int maximum) {
        return object.hasNonNull(field) ? boundedText(object, field, maximum) : null;
    }
    private static String boundedText(JsonNode object, String field, int maximum) {
        JsonNode value = object.path(field);
        if (!value.isTextual() || value.asText().isBlank() || value.asText().length() > maximum) {
            throw new IllegalArgumentException("Invalid bounded field");
        }
        return value.asText();
    }
    private static void allowFields(JsonNode object, Set<String> allowed) {
        if (!object.isObject()) throw new IllegalArgumentException("Object required");
        object.fieldNames().forEachRemaining(field -> {
            if (!allowed.contains(field)) throw new IllegalArgumentException("Unexpected field");
        });
    }
    private static String readLine(BufferedInputStream input) throws java.io.IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1 && value != '\n') {
            if (line.size() >= MAX_LINE_BYTES) throw new IllegalArgumentException("Input frame exceeds bound");
            line.write(value);
        }
        if (value == -1 && line.size() == 0) return null;
        return line.toString(StandardCharsets.UTF_8);
    }
}
