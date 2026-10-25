package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

/** Schema 3 extends, never reinterprets, the frozen schema-2 prefix.
 * Uses server timestamps/normalized categories only, never labels, identities,
 * raw URLs/agents, request bodies, provider fixtures or future history. */
public final class ContextualBehaviorFeatures {
    private static final Set<String> SENSITIVE = Set.of("PASSWORD_RESET", "PASSWORD_CHANGE", "EMAIL_CHANGE");
    private ContextualBehaviorFeatures() { }

    public static AccountBehaviorFeatures.Vector fromEvents(AccountBehaviorFeatures.Vector personal,
            AccountBaselinePolicy.Snapshot snapshot, List<SiemSecurityEvent> events) {
        if (personal == null || personal.featureSchemaVersion() != 2 || snapshot == null || events == null
                || events.stream().anyMatch(event -> event == null || event.getEventTimestamp() == null)) {
            throw new IllegalArgumentException("Valid personal snapshot and timestamped source events required.");
        }
        if (!events.isEmpty()) {
            LocalDateTime first = events.stream().map(SiemSecurityEvent::getEventTimestamp).min(LocalDateTime::compareTo).orElseThrow();
            LocalDateTime last = events.stream().map(SiemSecurityEvent::getEventTimestamp).max(LocalDateTime::compareTo).orElseThrow();
            if (first.isBefore(snapshot.asOf()) || !last.isBefore(snapshot.asOf().plusMinutes(15))
                    || Duration.between(first, last).compareTo(Duration.ofMinutes(15)) >= 0) {
                throw new IllegalArgumentException("All contextual events must belong to one 15-minute window.");
            }
        }
        List<SiemSecurityEvent> requests = events.stream().filter(event -> "HTTP_REQUEST".equals(event.getEventType()))
                .sorted(Comparator.comparing(SiemSecurityEvent::getEventTimestamp)
                        .thenComparing(event -> event.getRouteGroup() == null ? "" : event.getRouteGroup())
                        .thenComparing(event -> event.getHttpStatus() == null ? 0 : event.getHttpStatus())).toList();
        List<LocalDateTime> failed = events.stream().filter(event -> "AUTH".equals(event.getEventType())
                && "LOGIN".equals(event.getAction()) && "FAILURE".equals(event.getOutcome()))
                .map(SiemSecurityEvent::getEventTimestamp).sorted().toList();
        List<LocalDateTime> sensitive = events.stream().filter(event -> "DOMAIN_ACTION".equals(event.getEventType())
                && SENSITIVE.contains(event.getAction())).map(SiemSecurityEvent::getEventTimestamp).sorted().toList();
        if (requests.size() != personal.values().get(0) || failed.size() != personal.values().get(3)
                || sensitive.size() != personal.values().get(5)) {
            throw new IllegalArgumentException("Contextual source counts must match the immutable personal prefix.");
        }
        List<LocalDateTime> requestTimes = requests.stream().map(SiemSecurityEvent::getEventTimestamp).toList();
        List<Double> gaps = new ArrayList<>();
        for (int index = 1; index < requestTimes.size(); index++) {
            gaps.add(Duration.between(requestTimes.get(index - 1), requestTimes.get(index)).toNanos() / 1_000_000_000.0);
        }
        if (gaps.stream().anyMatch(gap -> gap < 0 || gap > 900)) throw new IllegalArgumentException("One 15-minute source window required.");
        double mean = gaps.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double variance = gaps.stream().mapToDouble(gap -> (gap - mean) * (gap - mean)).average().orElse(0);
        List<Double> ordered = gaps.stream().sorted().toList();
        double median = ordered.isEmpty() ? 0 : ordered.size() % 2 == 1 ? ordered.get(ordered.size() / 2)
                : (ordered.get(ordered.size() / 2 - 1) + ordered.get(ordered.size() / 2)) / 2;
        int transitions = 0;
        for (int index = 1; index < requests.size(); index++) {
            var left = requests.get(index - 1); var right = requests.get(index);
            // Do not infer a sequence between simultaneous requests from UUID order.
            if (right.getEventTimestamp().isAfter(left.getEventTimestamp()) && left.getRouteGroup() != null
                    && right.getRouteGroup() != null && !left.getRouteGroup().equals(right.getRouteGroup())) transitions++;
        }
        TreeMap<LocalDateTime, List<SiemSecurityEvent>> ties = new TreeMap<>();
        requests.forEach(event -> ties.computeIfAbsent(event.getEventTimestamp(), ignored -> new ArrayList<>()).add(event));
        int consecutive = 0, maximum = 0;
        for (var group : ties.values()) {
            if (group.stream().allMatch(event -> event.getHttpStatus() != null && event.getHttpStatus() >= 400 && event.getHttpStatus() < 500)) {
                consecutive += group.size(); maximum = Math.max(maximum, consecutive);
            } else consecutive = 0;
        }
        List<Double> values = new ArrayList<>(personal.values());
        values.add((double) peak(requestTimes, 10)); values.add(median);
        values.add(mean == 0 ? 0 : Math.min(20, Math.sqrt(variance) / mean));
        values.add((double) transitions); values.add(transitions / (double) Math.max(1, requests.size() - 1));
        values.add(AccountBehaviorFeatures.logMadDeviation(personal.values().get(3), snapshot, 3));
        values.add(AccountBehaviorFeatures.logMadDeviation(personal.values().get(5), snapshot, 5));
        values.add((double) peak(failed, 60)); values.add((double) peak(sensitive, 60)); values.add((double) maximum);
        return new AccountBehaviorFeatures.Vector(3, values);
    }

    /** Exact rolling interval (timestamp-seconds, timestamp], not fixed-bin peaks. */
    private static int peak(List<LocalDateTime> times, int seconds) {
        int left = 0, maximum = 0;
        for (int right = 0; right < times.size(); right++) {
            while (left <= right && !times.get(left).isAfter(times.get(right).minusSeconds(seconds))) left++;
            maximum = Math.max(maximum, right - left + 1);
        }
        return maximum;
    }
}
