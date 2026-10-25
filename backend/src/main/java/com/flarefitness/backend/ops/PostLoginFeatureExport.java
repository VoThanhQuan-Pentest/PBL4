package com.flarefitness.backend.ops;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.service.siem.AccountBaselinePolicy;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.ContextualBehaviorFeatures;
import com.flarefitness.backend.service.siem.PostLoginBehaviorFeatures;
import com.flarefitness.backend.service.siem.PostLoginRiskContextFeatures;
import com.flarefitness.backend.service.siem.SessionEndpointBehaviorFeatures;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Offline DEMO_ONLY precommit representation, separate from strict schema 4. No fitting or network. */
public final class PostLoginFeatureExport {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final Set<String> FRAME_FIELDS = Set.of("frame_id", "attempt", "context", "baseline_frames");
    private static final Set<String> EVENT_FIELDS = Set.of("event_id", "actor_user_id", "target_user_id", "event_type", "action",
            "outcome", "event_timestamp", "telemetry_contract_version", "session_pseudonym", "session_issued_at", "http_status",
            "endpoint_category", "http_method", "route_group", "source_ip", "user_agent_family");
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    private PostLoginFeatureExport() { }

    public static void main(String[] args) {
        if (args.length != 1 || !("--demo-only".equals(args[0]) || "--demo-risk-context-only".equals(args[0]))) {
            System.err.println("Usage: PostLoginFeatureExport --demo-only < frames.ndjson");
            System.exit(2);
        }
        try {
            var input = new BufferedInputStream(System.in);
            int count = 0;
            int warmups = 0;
            String warmupAccount = null;
            var history = new UebaFeatureExport.History();
            String line;
            while ((line = readLine(input)) != null) {
                if (++count > 200_000) throw new IllegalArgumentException("Frame bound exceeded");
                var frame = JSON.readTree(line);
                if (frame.isObject() && frame.size() == 1 && frame.has("baseline_frame")) {
                    if (++warmups > 96) throw new IllegalArgumentException("Warmup frame bound exceeded");
                    var prior = frame.path("baseline_frame");
                    String account = text(prior, "account_id", 64);
                    if (warmupAccount != null && !warmupAccount.equals(account)) throw new IllegalArgumentException("Mixed warmup accounts");
                    warmupAccount = account;
                    UebaFeatureExport.transform(prior, history, 4);
                    System.out.println(JSON.writeValueAsString(Map.of("warmup_frame_id", text(prior, "frame_id", 128))));
                } else {
                    if (warmupAccount != null && !warmupAccount.equals(text(frame.path("attempt"), "actor_user_id", 64))) {
                        throw new IllegalArgumentException("Warmup and attempt account differ");
                    }
                    System.out.println(JSON.writeValueAsString("--demo-risk-context-only".equals(args[0])
                            ? transformRisk(frame, history) : transform(frame, history)));
                    history = new UebaFeatureExport.History(); warmups = 0; warmupAccount = null;
                }
            }
            if (count == 0 || warmups != 0) throw new IllegalArgumentException("Complete non-empty episode input required");
        } catch (Exception failure) {
            System.err.println("Precommit feature export refused/failed: " + failure.getClass().getSimpleName());
            System.exit(2);
        }
    }

    static Map<String, Object> transform(JsonNode frame) {
        return transform(frame, new UebaFeatureExport.History());
    }

    static Map<String, Object> transformRisk(JsonNode frame, UebaFeatureExport.History history) {
        return transform(frame, history, true);
    }

    static Map<String, Object> transform(JsonNode frame, UebaFeatureExport.History history) {
        return transform(frame, history, false);
    }

    private static Map<String, Object> transform(JsonNode frame, UebaFeatureExport.History history, boolean rolling) {
        allow(frame, FRAME_FIELDS);
        String id = text(frame, "frame_id", 128);
        if (!id.matches("[a-z0-9_-]{8,128}")) throw new IllegalArgumentException("Pseudonymous frame ID required");
        SiemSecurityEvent attempt = event(frame.path("attempt"));
        String account = attempt.getActorUserId();
        if (account == null || !account.matches("[a-z0-9_-]{8,64}")) throw new IllegalArgumentException("Pseudonymous account required");
        var nodes = frame.path("context");
        if (!nodes.isArray() || nodes.size() > PostLoginBehaviorFeatures.MAXIMUM_CONTEXT_EVENTS) {
            throw new IllegalArgumentException("Bounded observed context required");
        }
        List<SiemSecurityEvent> context = new ArrayList<>();
        nodes.forEach(node -> context.add(event(node)));
        PostLoginBehaviorFeatures.beforeAttempt(attempt, context);
        LocalDateTime asOf = attempt.getEventTimestamp();
        LocalDateTime start = asOf.withMinute(asOf.getMinute() / 15 * 15).withSecond(0).withNano(0);
        var baselineFrames = frame.path("baseline_frames");
        if (!baselineFrames.isArray() || baselineFrames.size() > 96) throw new IllegalArgumentException("Bounded baseline frames required");
        for (var prior : baselineFrames) {
            if (!account.equals(text(prior, "account_id", 64)) || !timestamp(prior, "window_start").isBefore(start)) {
                throw new IllegalArgumentException("Baseline must belong to this account and precede the target window");
            }
            UebaFeatureExport.transform(prior, history, 4);
        }
        var previous = history.before(account, start);
        var observed = fromObserved(attempt, context, previous);
        var result = new java.util.LinkedHashMap<String, Object>(Map.of("frame_id", id, "representation_version", PostLoginBehaviorFeatures.VERSION,
                "baseline_feature_names", AccountBehaviorFeatures.names(4), "baseline_features", observed.baselineFeatures(),
                "postlogin_feature_names", observed.postlogin().names(), "postlogin_features", observed.postlogin().values(),
                "baseline_established", observed.baselineEstablished(), "trusted_window_count", observed.trustedWindowCount(),
                "data_provenance", "DEMO_ONLY", "before_current_outcome", true));
        if (rolling) {
            result.put("representation_version", PostLoginRiskContextFeatures.VERSION);
            result.put("feature_schema_version", PostLoginRiskContextFeatures.SCHEMA_VERSION);
            result.put("rolling_feature_names", PostLoginRiskContextFeatures.NAMES);
            result.put("rolling_features", PostLoginRiskContextFeatures.fromObserved(attempt, context, previous));
        }
        return result;
    }

    /**
     * Shared research export at a real server attempt. History must contain only this
     * account's closed windows before the current window. Empty history retains an
     * unestablished baseline; this method does not infer READY coverage or actor intent.
     */
    public static ObservedSnapshot fromObserved(SiemSecurityEvent attempt, List<SiemSecurityEvent> context,
                                                List<SiemAccountBehaviorWindow> previous) {
        var postlogin = PostLoginBehaviorFeatures.beforeAttempt(attempt, context);
        String account = attempt.getActorUserId();
        LocalDateTime asOf = attempt.getEventTimestamp();
        LocalDateTime start = asOf.withMinute(asOf.getMinute() / 15 * 15).withSecond(0).withNano(0);
        if (previous == null || previous.size() > AccountBaselinePolicy.MAX_OBSERVED_REQUEST_WINDOWS
                || previous.stream().anyMatch(window -> window == null || !account.equals(window.getAccountId())
                    || window.getWindowStart() == null || window.getWindowEnd() == null
                    || !window.getWindowEnd().isAfter(window.getWindowStart())
                    || !window.getWindowStart().isBefore(start) || window.getWindowEnd().isAfter(start))) {
            throw new IllegalArgumentException("Bounded same-account closed history before the current window required");
        }
        var baseline = AccountBaselinePolicy.summarize(previous, start, ZONE);
        // Only events already observable at the attempt; current outcome and future
        // HTTP completion are unavailable to this prefix. Empty prefix is legitimate.
        var current = context.stream().filter(e -> !e.getEventTimestamp().isBefore(start) && e.getEventTimestamp().isBefore(asOf)
                && (account.equals(e.getActorUserId()) || e.getActorUserId() == null && account.equals(e.getTargetUserId()))
                && Set.of("HTTP_REQUEST", "AUTH", "DOMAIN_ACTION").contains(e.getEventType())).toList();
        var raw = AccountBehaviorFeatures.fromEvents(current, baseline.features(), ZONE);
        var personal = AccountBehaviorFeatures.withPersonalFeatures(raw, baseline);
        var contextual = ContextualBehaviorFeatures.fromEvents(personal, baseline, current);
        var prefix = SessionEndpointBehaviorFeatures.fromEvents(contextual,
                AccountBaselinePolicy.observedRequests(previous, start), start, current);
        return new ObservedSnapshot(prefix.values(), postlogin, baseline.features().established(), baseline.trustedWindows());
    }

    public record ObservedSnapshot(List<Double> baselineFeatures, PostLoginBehaviorFeatures.Snapshot postlogin,
                                   boolean baselineEstablished, int trustedWindowCount) {
        public ObservedSnapshot { baselineFeatures = List.copyOf(baselineFeatures); }
    }

    /** Same schema6 used by the offline exporter, observed before the current outcome. */
    public static RiskSnapshot fromObservedRisk(SiemSecurityEvent attempt, List<SiemSecurityEvent> context,
                                                List<SiemAccountBehaviorWindow> previous) {
        var observed = fromObserved(attempt, context, previous);
        return new RiskSnapshot(observed,
                PostLoginRiskContextFeatures.fromObserved(attempt, context, previous));
    }

    public record RiskSnapshot(ObservedSnapshot observed, List<Double> rollingFeatures) {
        public RiskSnapshot { rollingFeatures = List.copyOf(rollingFeatures); }
        public List<Double> values() {
            var values = new ArrayList<Double>(observed.baselineFeatures());
            values.addAll(observed.postlogin().values()); values.addAll(rollingFeatures);
            return List.copyOf(values);
        }
    }

    private static SiemSecurityEvent event(JsonNode node) {
        allow(node, EVENT_FIELDS);
        var event = new SiemSecurityEvent();
        event.setId(optional(node, "event_id", 128)); event.setActorUserId(optional(node, "actor_user_id", 64));
        event.setTargetUserId(optional(node, "target_user_id", 64));
        event.setEventType(text(node, "event_type", 48)); event.setAction(text(node, "action", 80));
        event.setOutcome(text(node, "outcome", 16)); event.setEventTimestamp(timestamp(node, "event_timestamp"));
        if (!Set.of("HTTP_REQUEST", "AUTH", "DOMAIN_ACTION", "SENSITIVE_ACTION_ATTEMPT").contains(event.getEventType())
                || !Set.of("SUCCESS", "FAILURE", "ATTEMPT").contains(event.getOutcome())) throw new IllegalArgumentException("Unknown observed event semantics");
        if (node.hasNonNull("telemetry_contract_version")) {
            if (!node.path("telemetry_contract_version").isIntegralNumber()
                    || !Set.of(3, 4).contains(node.path("telemetry_contract_version").asInt())) throw new IllegalArgumentException("Unknown telemetry contract");
            event.setTelemetryContractVersion(node.path("telemetry_contract_version").asInt());
        }
        event.setSessionPseudonym(optional(node, "session_pseudonym", 64));
        if (node.hasNonNull("session_issued_at")) event.setSessionIssuedAt(timestamp(node, "session_issued_at"));
        if ((event.getSessionPseudonym() == null) != (event.getSessionIssuedAt() == null)
                || event.getSessionPseudonym() != null && (!event.getSessionPseudonym().matches("[0-9a-f]{64}")
                    || event.getSessionIssuedAt().isAfter(event.getEventTimestamp()))) throw new IllegalArgumentException("Invalid observed session metadata");
        if (node.hasNonNull("http_status")) {
            if (!node.path("http_status").isIntegralNumber()) throw new IllegalArgumentException("Invalid HTTP status");
            int status = node.path("http_status").asInt();
            if (status < 100 || status > 599) throw new IllegalArgumentException("Invalid HTTP status");
            event.setHttpStatus(status);
        }
        event.setEndpointCategory(optional(node, "endpoint_category", 64));
        event.setHttpMethod(optional(node, "http_method", 8)); event.setRouteGroup(optional(node, "route_group", 64));
        event.setSourceIp(optional(node, "source_ip", 64)); event.setUserAgentFamily(optional(node, "user_agent_family", 32));
        return event;
    }

    private static LocalDateTime timestamp(JsonNode node, String field) {
        return LocalDateTime.ofInstant(Instant.parse(text(node, field, 40)), ZoneOffset.UTC);
    }
    private static String optional(JsonNode node, String field, int maximum) {
        return node.hasNonNull(field) ? text(node, field, maximum) : null;
    }
    private static String text(JsonNode node, String field, int maximum) {
        var value = node.path(field);
        if (!value.isTextual() || value.asText().isBlank() || value.asText().length() > maximum) throw new IllegalArgumentException("Bounded text required");
        return value.asText();
    }
    private static void allow(JsonNode node, Set<String> fields) {
        if (!node.isObject()) throw new IllegalArgumentException("Object required");
        node.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw new IllegalArgumentException("Unexpected field"); });
    }
    private static String readLine(BufferedInputStream input) throws java.io.IOException {
        var bytes = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1 && value != '\n') {
            if (bytes.size() >= 2 * 1024 * 1024) throw new IllegalArgumentException("Frame byte bound exceeded");
            bytes.write(value);
        }
        return value == -1 && bytes.size() == 0 ? null : bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
    }
}
