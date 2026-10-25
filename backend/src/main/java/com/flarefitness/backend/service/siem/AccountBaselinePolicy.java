package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** One temporal/trust policy for aggregation, personal features and account summaries. */
public final class AccountBaselinePolicy {
    public static final int HISTORY_DAYS = 14;
    public static final int REQUIRED_WINDOWS = 30;
    public static final int MAX_OBSERVED_REQUEST_WINDOWS = HISTORY_DAYS * 24 * 4;
    // Used by the bounded aggregate query, with the same predicate as isTrusted().
    public static final String TRUSTED_HQL = "w.http4xxCount = 0 and w.http5xxCount = 0 "
            + "and w.failedLoginCount = 0 and w.sensitiveActionCount = 0 "
            + "and w.newIpFlag = false and w.newUserAgentFlag = false and w.eventCount > 0 "
            + "and w.demoLabel not in ('ABNORMAL','MIXED') "
            + "and (w.riskScore is null or w.riskScore < 30)";

    private AccountBaselinePolicy() { }

    public static boolean isTrusted(SiemAccountBehaviorWindow window) {
        return window.getHttp4xxCount() == 0 && window.getHttp5xxCount() == 0
                && window.getFailedLoginCount() == 0 && window.getSensitiveActionCount() == 0
                && !window.isNewIpFlag() && !window.isNewUserAgentFlag()
                && window.getEventCount() > 0
                && !Set.of("ABNORMAL", "MIXED").contains(window.getDemoLabel())
                && (window.getRiskScore() == null || window.getRiskScore() < 30);
    }

    public static Snapshot summarize(List<SiemAccountBehaviorWindow> history, LocalDateTime asOf,
                                      ZoneId behaviorZone) {
        if (history == null || asOf == null || behaviorZone == null) {
            throw new IllegalArgumentException("History, as-of time and behavior zone are required.");
        }
        Map<LocalDateTime, SiemAccountBehaviorWindow> unique = new LinkedHashMap<>();
        for (SiemAccountBehaviorWindow window : history) {
            if (window == null || window.getWindowStart() == null || window.getWindowEnd() == null) {
                throw new IllegalArgumentException("History windows require start and end timestamps.");
            }
            if (window.getWindowStart().isBefore(asOf.minusDays(HISTORY_DAYS))
                    || !window.getWindowStart().isBefore(asOf) || window.getWindowEnd().isAfter(asOf)) continue;
            unique.merge(window.getWindowStart(), window, (left, right) ->
                    right.getFeatureSchemaVersion() > left.getFeatureSchemaVersion() ? right : left);
        }
        List<SiemAccountBehaviorWindow> trusted = unique.values().stream()
                .filter(AccountBaselinePolicy::isTrusted).toList();
        String status = status(unique.size(), trusted.size());
        if (!"READY".equals(status)) {
            return new Snapshot(status, trusted.size(), asOf,
                    AccountBehaviorFeatures.Baseline.insufficientHistory(), trusted);
        }
        Map<Integer, Set<LocalDate>> hourDays = new HashMap<>();
        Set<String> seenIps = new HashSet<>();
        Set<String> seenUserAgents = new HashSet<>();
        for (SiemAccountBehaviorWindow window : trusted) {
            var local = window.getWindowStart().atOffset(ZoneOffset.UTC).atZoneSameInstant(behaviorZone);
            hourDays.computeIfAbsent(local.getHour(), ignored -> new HashSet<>()).add(local.toLocalDate());
            if (window.getSourceIp() != null) seenIps.add(window.getSourceIp());
            if (window.getUserAgentFamily() != null) seenUserAgents.add(window.getUserAgentFamily());
        }
        Set<Integer> usualHours = new HashSet<>();
        hourDays.forEach((hour, days) -> { if (days.size() >= 2) usualHours.add(hour); });
        return new Snapshot(status, trusted.size(), asOf,
                new AccountBehaviorFeatures.Baseline(true, seenIps, seenUserAgents, usualHours), trusted);
    }

    public static String status(long historyWindows, long trustedWindows) {
        return historyWindows == 0 ? "NO_DATA"
                : trustedWindows < REQUIRED_WINDOWS ? "INSUFFICIENT_HISTORY" : "READY";
    }

    /**
     * Schema 4's short history is observed HTTP activity, not the trusted/ready
     * baseline. Labels, provider fixtures and model/rule risk are not selectors.
     */
    public static ObservedRequestHistory observedRequests(List<SiemAccountBehaviorWindow> history,
                                                          LocalDateTime asOf) {
        if (history == null || asOf == null) {
            throw new IllegalArgumentException("Observed history and as-of time are required.");
        }
        Map<LocalDateTime, SiemAccountBehaviorWindow> unique = new LinkedHashMap<>();
        for (SiemAccountBehaviorWindow window : history) {
            if (window == null || window.getWindowStart() == null || window.getWindowEnd() == null
                    || !window.getWindowEnd().isAfter(window.getWindowStart())) {
                throw new IllegalArgumentException("Observed history windows require valid start and end timestamps.");
            }
            if (window.getWindowStart().isBefore(asOf.minusDays(HISTORY_DAYS))
                    || !window.getWindowStart().isBefore(asOf) || window.getWindowEnd().isAfter(asOf)
                    || window.featureVector().get(0) <= 0) continue;
            unique.merge(window.getWindowStart(), window, (left, right) ->
                    right.getFeatureSchemaVersion() > left.getFeatureSchemaVersion() ? right : left);
        }
        List<Double> logs = unique.values().stream()
                .sorted(Comparator.comparing(SiemAccountBehaviorWindow::getWindowStart).reversed())
                .limit(MAX_OBSERVED_REQUEST_WINDOWS).map(window -> Math.log1p(window.featureVector().get(0)))
                .sorted().toList();
        int middle = logs.size() / 2;
        double center = logs.isEmpty() ? 0 : logs.size() % 2 == 1 ? logs.get(middle)
                : (logs.get(middle - 1) + logs.get(middle)) / 2;
        return new ObservedRequestHistory(logs.size(), center);
    }

    public record ObservedRequestHistory(int windowCount, double medianLogRequestCount) {
        public ObservedRequestHistory {
            if (windowCount < 0 || windowCount > MAX_OBSERVED_REQUEST_WINDOWS
                    || !Double.isFinite(medianLogRequestCount) || medianLogRequestCount < 0
                    || (windowCount == 0 && medianLogRequestCount != 0)) {
                throw new IllegalArgumentException("Invalid observed request history summary.");
            }
        }
    }

    public record Snapshot(String status, int trustedWindows, LocalDateTime asOf,
                           AccountBehaviorFeatures.Baseline features,
                           List<SiemAccountBehaviorWindow> trustedHistory) {
        public Snapshot { trustedHistory = List.copyOf(trustedHistory); }
    }
}
