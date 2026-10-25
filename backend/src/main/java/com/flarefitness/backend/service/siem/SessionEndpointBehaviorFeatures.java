package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Schema 4 appends observed server metadata to the immutable schema-3 prefix.
 * Identifiers are grouping keys only; no identity, raw path, label or fixture
 * value enters the numeric vector. Missing legacy telemetry stays uncovered. */
public final class SessionEndpointBehaviorFeatures {
    private static final Pattern SESSION_PSEUDONYM = Pattern.compile("[0-9a-f]{64}");
    private static final Set<String> WRITE_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final Map<EndpointCategory, Set<EndpointCategory>> WORKFLOWS = Map.of(
            EndpointCategory.PRODUCT_LIST, Set.of(EndpointCategory.PRODUCT_DETAIL),
            EndpointCategory.PROFILE_READ, Set.of(EndpointCategory.PROFILE_UPDATE, EndpointCategory.PROFILE_EMAIL_OTP,
                    EndpointCategory.PROFILE_PASSWORD),
            EndpointCategory.ORDERS_READ, Set.of(EndpointCategory.ORDER_CANCEL, EndpointCategory.ORDER_RETURN),
            EndpointCategory.SUPPORT_READ, Set.of(EndpointCategory.SUPPORT_SEND),
            EndpointCategory.REVIEW_READ, Set.of(EndpointCategory.REVIEW_CREATE),
            EndpointCategory.PROMO_LIST, Set.of(EndpointCategory.PROMO_CLAIM),
            EndpointCategory.SYNC_READ, Set.of(EndpointCategory.SYNC_WRITE));

    private SessionEndpointBehaviorFeatures() { }

    public static AccountBehaviorFeatures.Vector fromEvents(AccountBehaviorFeatures.Vector contextual,
            AccountBaselinePolicy.ObservedRequestHistory history, LocalDateTime asOf, List<SiemSecurityEvent> events) {
        if (contextual == null || contextual.featureSchemaVersion() != AccountBehaviorFeatures.CONTEXTUAL_SCHEMA_VERSION
                || history == null || asOf == null || events == null
                || events.stream().anyMatch(event -> event == null || event.getEventTimestamp() == null)) {
            throw new IllegalArgumentException("Valid contextual snapshot, observed history and source events required.");
        }
        if (events.stream().anyMatch(event -> event.getEventTimestamp().isBefore(asOf)
                || !event.getEventTimestamp().isBefore(asOf.plusMinutes(15)))) {
            throw new IllegalArgumentException("All session/endpoint events must belong to one 15-minute window.");
        }
        List<SiemSecurityEvent> requests = events.stream()
                .filter(event -> "HTTP_REQUEST".equals(event.getEventType())).toList();
        if (requests.size() != contextual.values().get(0)) {
            throw new IllegalArgumentException("Session/endpoint source counts must match the contextual prefix.");
        }
        int endpointCount = 0, unmatched = 0, unresolved = 0, writes = 0, sessionCount = 0;
        double minimumAge = 86400;
        Set<EndpointCategory> categories = new HashSet<>();
        Map<EndpointCategory, List<LocalDateTime>> endpointTimes = new HashMap<>();
        Map<String, TreeMap<LocalDateTime, List<SiemSecurityEvent>>> sessionRequests = new HashMap<>();
        for (SiemSecurityEvent event : requests) {
            if (!Integer.valueOf(3).equals(event.getTelemetryContractVersion())) continue;
            var category = EndpointCategory.fromStored(event.getEndpointCategory());
            if (category.isPresent()) {
                endpointCount++;
                if (category.get() == EndpointCategory.UNMATCHED) unmatched++;
                else if (category.get() == EndpointCategory.UNRESOLVED) unresolved++;
                else {
                    categories.add(category.get());
                    endpointTimes.computeIfAbsent(category.get(), ignored -> new ArrayList<>()).add(event.getEventTimestamp());
                    if (event.getHttpMethod() != null && WRITE_METHODS.contains(event.getHttpMethod())) writes++;
                }
            }
            if (hasAuthenticatedSession(event)) {
                sessionCount++;
                Duration age = Duration.between(event.getSessionIssuedAt(), event.getEventTimestamp());
                double seconds = age.compareTo(Duration.ofDays(1)) >= 0 ? 86400
                        : age.getSeconds() + age.getNano() / 1_000_000_000.0;
                minimumAge = Math.min(minimumAge, seconds);
                sessionRequests.computeIfAbsent(event.getSessionPseudonym(), ignored -> new TreeMap<>())
                        .computeIfAbsent(event.getEventTimestamp(), ignored -> new ArrayList<>()).add(event);
            }
        }
        int endpointPeak = endpointTimes.values().stream().mapToInt(SessionEndpointBehaviorFeatures::peak).max().orElse(0);
        int transitions = sessionRequests.values().stream().mapToInt(SessionEndpointBehaviorFeatures::workflowTransitions).sum();
        double shortRatio = history.windowCount() == 0 ? 0 : Math.max(-20, Math.min(20,
                Math.log1p(requests.size()) - history.medianLogRequestCount()));
        List<Double> values = new ArrayList<>(contextual.values());
        values.add((double) endpointCount); values.add((double) categories.size());
        values.add((double) unmatched); values.add((double) unresolved); values.add((double) writes);
        values.add((double) endpointPeak); values.add((double) sessionCount); values.add((double) sessionRequests.size());
        values.add(sessionCount == 0 ? 0 : minimumAge); values.add((double) transitions);
        values.add((double) history.windowCount()); values.add(shortRatio);
        return new AccountBehaviorFeatures.Vector(AccountBehaviorFeatures.SESSION_ENDPOINT_SCHEMA_VERSION, values);
    }

    private static boolean hasAuthenticatedSession(SiemSecurityEvent event) {
        return event.getActorUserId() != null && !event.getActorUserId().isBlank()
                && event.getSessionPseudonym() != null && SESSION_PSEUDONYM.matcher(event.getSessionPseudonym()).matches()
                && event.getSessionIssuedAt() != null && !event.getSessionIssuedAt().isAfter(event.getEventTimestamp());
    }

    private static int workflowTransitions(TreeMap<LocalDateTime, List<SiemSecurityEvent>> requests) {
        SiemSecurityEvent previous = null;
        int count = 0;
        for (List<SiemSecurityEvent> simultaneous : requests.values()) {
            // A tie is not a sequence, and must not be bridged by sorting UUIDs/categories.
            if (simultaneous.size() != 1) { previous = null; continue; }
            SiemSecurityEvent current = simultaneous.get(0);
            if (previous != null && successful(previous) && successful(current)
                    && current.getEventTimestamp().isAfter(previous.getEventTimestamp())
                    && !current.getEventTimestamp().isAfter(previous.getEventTimestamp().plusSeconds(120))) {
                var left = EndpointCategory.fromStored(previous.getEndpointCategory());
                var right = EndpointCategory.fromStored(current.getEndpointCategory());
                if (left.isPresent() && right.isPresent()
                        && WORKFLOWS.getOrDefault(left.get(), Set.of()).contains(right.get())) count++;
            }
            previous = current;
        }
        return count;
    }

    private static boolean successful(SiemSecurityEvent event) {
        return event.getHttpStatus() != null && event.getHttpStatus() >= 200 && event.getHttpStatus() < 300;
    }

    /** Exact rolling interval (timestamp - 10 seconds, timestamp], per matched category. */
    private static int peak(List<LocalDateTime> timestamps) {
        List<LocalDateTime> times = timestamps.stream().sorted().toList();
        int left = 0, maximum = 0;
        for (int right = 0; right < times.size(); right++) {
            while (left <= right && !times.get(left).isAfter(times.get(right).minusSeconds(10))) left++;
            maximum = Math.max(maximum, right - left + 1);
        }
        return maximum;
    }
}
