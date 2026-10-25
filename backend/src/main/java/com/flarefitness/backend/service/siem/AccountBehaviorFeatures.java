package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Version 1 of the Spring-to-UEBA numeric feature contract. The order of this
 * vector is persisted and must never be changed without a schema version bump.
 */
public final class AccountBehaviorFeatures {
    public static final int SCHEMA_VERSION = 1;
    public static final int FEATURE_COUNT = 11;
    public static final int PERSONAL_SCHEMA_VERSION = 2;
    public static final int CONTEXTUAL_SCHEMA_VERSION = 3;
    public static final int SESSION_ENDPOINT_SCHEMA_VERSION = 4;

    public static final List<String> NAMES = List.of(
            "request_count", "http_4xx_count", "http_5xx_count",
            "failed_login_count", "successful_login_count", "sensitive_action_count",
            "distinct_route_group_count", "distinct_source_ip_count",
            "new_ip_flag", "new_user_agent_flag", "unusual_hour_flag");
    public static final List<String> PERSONAL_NAMES = java.util.stream.Stream.concat(NAMES.stream(),
            java.util.stream.Stream.of("request_log_mad_deviation", "route_group_log_mad_deviation",
                    "http_client_error_rate", "failed_login_rate")).toList();
    public static final List<String> CONTEXTUAL_NAMES = java.util.stream.Stream.concat(PERSONAL_NAMES.stream(),
            java.util.stream.Stream.of("request_peak_10s", "request_gap_median_seconds", "request_gap_cv",
                    "route_transition_count", "route_transition_rate", "failed_login_log_mad_deviation",
                    "sensitive_action_log_mad_deviation", "failed_login_peak_60s", "sensitive_action_peak_60s",
                    "consecutive_client_error_peak")).toList();
    public static final List<String> SESSION_ENDPOINT_NAMES = java.util.stream.Stream.concat(CONTEXTUAL_NAMES.stream(),
            java.util.stream.Stream.of("endpoint_metadata_count", "distinct_endpoint_category_count",
                    "unmatched_endpoint_request_count", "unresolved_endpoint_request_count", "write_request_count",
                    "same_endpoint_peak_10s", "session_metadata_count", "distinct_authenticated_session_count",
                    "minimum_authenticated_session_age_seconds", "workflow_transition_count",
                    "prior_request_window_count", "short_history_request_log_ratio")).toList();

    private AccountBehaviorFeatures() { }

    public static Vector fromEvents(List<SiemSecurityEvent> events, Baseline baseline, ZoneId behaviorZone) {
        if (events == null || baseline == null || behaviorZone == null) {
            throw new IllegalArgumentException("Events, baseline and behavior zone are required.");
        }
        int requests = 0;
        int clientErrors = 0;
        int serverErrors = 0;
        int failedLogins = 0;
        int successfulLogins = 0;
        int sensitiveActions = 0;
        boolean newIp = false;
        boolean newUserAgent = false;
        boolean unusualHour = false;
        Set<String> routeGroups = new HashSet<>();
        Set<String> sourceIps = new HashSet<>();

        for (SiemSecurityEvent event : events) {
            if (event == null || event.getEventTimestamp() == null) {
                throw new IllegalArgumentException("Every security event needs a timestamp.");
            }
            if ("HTTP_REQUEST".equals(event.getEventType())) {
                requests++;
                Integer status = event.getHttpStatus();
                if (status != null && status >= 400 && status < 500) clientErrors++;
                if (status != null && status >= 500 && status < 600) serverErrors++;
                if (event.getRouteGroup() != null) routeGroups.add(event.getRouteGroup());
            } else if ("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction())) {
                if ("FAILURE".equals(event.getOutcome())) failedLogins++;
                if ("SUCCESS".equals(event.getOutcome())) successfulLogins++;
            } else if ("DOMAIN_ACTION".equals(event.getEventType())
                    && Set.of("PASSWORD_RESET", "PASSWORD_CHANGE", "EMAIL_CHANGE")
                    .contains(event.getAction())) {
                sensitiveActions++;
            }

            if (event.getSourceIp() != null && !event.getSourceIp().isBlank()) {
                sourceIps.add(event.getSourceIp());
                if (baseline.established() && !baseline.seenIps().isEmpty()
                        && !baseline.seenIps().contains(event.getSourceIp())) newIp = true;
            }
            if (event.getUserAgentFamily() != null && !event.getUserAgentFamily().isBlank()
                    && baseline.established() && !baseline.seenUserAgents().isEmpty()
                    && !baseline.seenUserAgents().contains(event.getUserAgentFamily())) {
                newUserAgent = true;
            }
            int localHour = event.getEventTimestamp().atOffset(ZoneOffset.UTC)
                    .atZoneSameInstant(behaviorZone).getHour();
            if (baseline.established() && !baseline.usualHours().isEmpty()
                    && !baseline.usualHours().contains(localHour)) unusualHour = true;
        }

        List<Double> values = List.of((double) requests, (double) clientErrors, (double) serverErrors,
                (double) failedLogins, (double) successfulLogins, (double) sensitiveActions,
                (double) routeGroups.size(), (double) sourceIps.size(),
                newIp ? 1.0 : 0.0, newUserAgent ? 1.0 : 0.0, unusualHour ? 1.0 : 0.0);
        return new Vector(SCHEMA_VERSION, values);
    }

    public static List<String> names(int schema) {
        if (schema == SCHEMA_VERSION) return NAMES;
        if (schema == PERSONAL_SCHEMA_VERSION) return PERSONAL_NAMES;
        if (schema == CONTEXTUAL_SCHEMA_VERSION) return CONTEXTUAL_NAMES;
        if (schema == SESSION_ENDPOINT_SCHEMA_VERSION) return SESSION_ENDPOINT_NAMES;
        throw new IllegalArgumentException("Incompatible feature schema.");
    }

    /** Personal history is a past-only snapshot; insufficient history never fabricates a deviation. */
    public static Vector withPersonalFeatures(Vector base, AccountBaselinePolicy.Snapshot snapshot) {
        if (base == null || base.featureSchemaVersion() != SCHEMA_VERSION || snapshot == null) {
            throw new IllegalArgumentException("Base features and baseline snapshot are required.");
        }
        List<Double> values = new ArrayList<>(base.values());
        values.add(logMadDeviation(base.values().get(0), snapshot, 0));
        values.add(logMadDeviation(base.values().get(6), snapshot, 6));
        values.add(base.values().get(1) / Math.max(1, base.values().get(0)));
        values.add(base.values().get(3) / Math.max(1, base.values().get(3) + base.values().get(4)));
        return new Vector(PERSONAL_SCHEMA_VERSION, values);
    }

    static double logMadDeviation(double current, AccountBaselinePolicy.Snapshot snapshot, int feature) {
        if (!snapshot.features().established()) return 0;
        List<Double> history = snapshot.trustedHistory().stream()
                .map(window -> Math.log1p(window.featureVector().get(feature))).sorted().toList();
        double center = median(history);
        double mad = median(history.stream().map(value -> Math.abs(value - center)).sorted().toList());
        return Math.max(-20, Math.min(20, (Math.log1p(current) - center) / Math.max(0.25, mad)));
    }

    private static double median(List<Double> sorted) {
        if (sorted.isEmpty()) throw new IllegalArgumentException("Ready baseline cannot have empty trusted history.");
        int middle = sorted.size() / 2;
        return sorted.size() % 2 == 1 ? sorted.get(middle) : (sorted.get(middle - 1) + sorted.get(middle)) / 2;
    }

    public record Baseline(boolean established, Set<String> seenIps,
                           Set<String> seenUserAgents, Set<Integer> usualHours) {
        public Baseline {
            if (seenIps == null || seenUserAgents == null || usualHours == null
                    || usualHours.stream().anyMatch(hour -> hour == null || hour < 0 || hour > 23)) {
                throw new IllegalArgumentException("Baseline sets and hours must be valid.");
            }
            seenIps = Set.copyOf(seenIps);
            seenUserAgents = Set.copyOf(seenUserAgents);
            usualHours = Set.copyOf(usualHours);
        }

        public static Baseline insufficientHistory() {
            return new Baseline(false, Set.of(), Set.of(), Set.of());
        }
    }

    public record Vector(int featureSchemaVersion, List<Double> values) {
        public Vector {
            if (values == null || values.size() != names(featureSchemaVersion).size()
                    || values.stream().anyMatch(value -> value == null || !Double.isFinite(value))) {
                throw new IllegalArgumentException("Invalid UEBA feature vector.");
            }
            if (featureSchemaVersion == SESSION_ENDPOINT_SCHEMA_VERSION) validateSessionEndpointValues(values);
            values = List.copyOf(values);
        }

        public Vector base() { return new Vector(SCHEMA_VERSION, values.subList(0, FEATURE_COUNT)); }
    }

    private static void validateSessionEndpointValues(List<Double> values) {
        if (values.stream().anyMatch(value -> Math.abs(value) > 1_000_000)) {
            throw new IllegalArgumentException("Bounded schema4 feature magnitudes required.");
        }
        for (int index = 0; index < 8; index++) {
            double value = values.get(index);
            if (value < 0 || value != Math.rint(value)) throw new IllegalArgumentException("Nonnegative integer source counts required.");
        }
        for (int index = 8; index < 11; index++) {
            if (values.get(index) != 0 && values.get(index) != 1) throw new IllegalArgumentException("Binary novelty flags required.");
        }
        if (values.get(1) + values.get(2) > values.get(0) || values.get(6) > values.get(0)
                || Math.abs(values.get(11)) > 20 || Math.abs(values.get(12)) > 20
                || Math.abs(values.get(13) - values.get(1) / Math.max(1, values.get(0))) > 1e-9
                || Math.abs(values.get(14) - values.get(3) / Math.max(1, values.get(3) + values.get(4))) > 1e-9) {
            throw new IllegalArgumentException("Source prefix counts and rates are inconsistent.");
        }
        for (int index : new int[] {15, 18, 22, 23, 24}) {
            if (values.get(index) < 0 || values.get(index) != Math.rint(values.get(index))) {
                throw new IllegalArgumentException("Nonnegative integer contextual counts required.");
            }
        }
        if (values.get(15) > values.get(0) || values.get(18) > Math.max(0, values.get(0) - 1)
                || values.get(22) > values.get(3) || values.get(23) > values.get(5) || values.get(24) > values.get(1)
                || values.get(0) > 0 && values.get(15) < 1 || values.get(3) > 0 && values.get(22) < 1
                || values.get(5) > 0 && values.get(23) < 1 || values.get(16) < 0 || values.get(16) >= 900
                || values.get(17) < 0 || values.get(17) > 20 || Math.abs(values.get(20)) > 20 || Math.abs(values.get(21)) > 20
                || values.get(0) < 2 && (values.get(16) != 0 || values.get(17) != 0)
                || Math.abs(values.get(19) - values.get(18) / Math.max(1, values.get(0) - 1)) > 1e-9) {
            throw new IllegalArgumentException("Contextual prefix differs from source totals.");
        }
        for (int index : new int[] {0, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35}) {
            double value = values.get(index);
            if (value < 0 || value > Integer.MAX_VALUE || value != Math.rint(value)) {
                throw new IllegalArgumentException("Session/endpoint feature counts must be nonnegative integers.");
            }
        }
        double requests = values.get(0), endpoints = values.get(25), sessions = values.get(31);
        double matched = endpoints - values.get(27) - values.get(28);
        if (endpoints > requests || sessions > requests || matched < 0
                || values.get(26) > matched || values.get(26) > 20 || values.get(29) > matched || values.get(30) > matched
                || values.get(32) > sessions || values.get(34) > Math.max(0, sessions - values.get(32))
                || (matched == 0 && (values.get(26) != 0 || values.get(30) != 0))
                || (matched > 0 && (values.get(26) < 1 || values.get(30) < 1))
                || (sessions > 0 && values.get(32) < 1)
                || values.get(33) < 0 || values.get(33) > 86400 || (sessions == 0 && values.get(33) != 0)
                || values.get(35) > AccountBaselinePolicy.MAX_OBSERVED_REQUEST_WINDOWS
                || values.get(36) < -20 || values.get(36) > 20 || (values.get(35) == 0 && values.get(36) != 0)) {
            throw new IllegalArgumentException("Inconsistent session/endpoint feature coverage.");
        }
    }
}
