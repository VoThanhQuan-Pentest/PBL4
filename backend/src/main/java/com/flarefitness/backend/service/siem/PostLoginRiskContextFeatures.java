package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Rolling account evidence lost by a current-window prefix or a same-session-only view. */
public final class PostLoginRiskContextFeatures {
    public static final String VERSION = "postlogin-risk-rolling-account-v2";
    public static final int SCHEMA_VERSION = 6;
    public static final List<String> NAMES = List.of(
            "prior_http_requests_account_15m", "prior_endpoint_categories_account_15m",
            "prior_http_4xx_account_15m", "prior_http_5xx_account_15m",
            "prior_target_associated_failed_logins_account_15m", "prior_sensitive_attempts_account_15m",
            "closed_history_request_median", "closed_history_request_median_available");

    private PostLoginRiskContextFeatures() { }

    public static List<Double> fromObserved(SiemSecurityEvent attempt, List<SiemSecurityEvent> context,
            List<SiemAccountBehaviorWindow> history) {
        PostLoginBehaviorFeatures.beforeAttempt(attempt, context);
        String account = attempt.getActorUserId();
        LocalDateTime at = attempt.getEventTimestamp();
        LocalDateTime start = at.withMinute(at.getMinute() / 15 * 15).withSecond(0).withNano(0);
        if (history == null || history.size() > 96) throw new IllegalArgumentException("Bounded closed history required");
        List<Double> requestsHistory = new ArrayList<>();
        Set<LocalDateTime> windows = new HashSet<>();
        for (var window : history) {
            if (window == null || !account.equals(window.getAccountId()) || window.getWindowStart() == null
                    || window.getWindowEnd() == null || !window.getWindowEnd().isAfter(window.getWindowStart())
                    || window.getWindowEnd().isAfter(start) || !windows.add(window.getWindowStart())) {
                throw new IllegalArgumentException("Unique same-account closed past windows required");
            }
            double requests = window.featureVector().get(0);
            if (!Double.isFinite(requests) || requests < 0) throw new IllegalArgumentException("Invalid history count");
            requestsHistory.add(requests);
        }
        int http = 0, errors4 = 0, errors5 = 0, failed = 0, sensitive = 0;
        Set<String> endpoints = new HashSet<>(), seen = new HashSet<>();
        for (var event : context) {
            if (!event.getEventTimestamp().isBefore(at)) continue;
            if (event.getId() != null && !seen.add(event.getId())) throw new IllegalArgumentException("Duplicate event identity");
            if (!event.getEventTimestamp().isAfter(at.minusMinutes(15))) continue;
            boolean actor = account.equals(event.getActorUserId());
            boolean targetFailure = event.getActorUserId() == null && account.equals(event.getTargetUserId())
                    && "AUTH".equals(event.getEventType());
            if (!actor && !targetFailure) continue;
            if ("HTTP_REQUEST".equals(event.getEventType())) {
                http++;
                if (event.getEndpointCategory() != null && !event.getEndpointCategory().isBlank()) endpoints.add(event.getEndpointCategory());
                Integer status = event.getHttpStatus();
                if (status != null && status >= 400 && status < 500) errors4++;
                if (status != null && status >= 500 && status < 600) errors5++;
            } else if ("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction())
                    && !"SUCCESS".equals(event.getOutcome())) {
                failed++;
            } else if ("SENSITIVE_ACTION_ATTEMPT".equals(event.getEventType())
                    && Set.of("EMAIL_CHANGE", "PASSWORD_CHANGE").contains(event.getAction())) {
                sensitive++;
            }
        }
        requestsHistory.sort(Double::compare);
        int middle = requestsHistory.size() / 2;
        double median = requestsHistory.isEmpty() ? 0 : requestsHistory.size() % 2 == 1
                ? requestsHistory.get(middle) : (requestsHistory.get(middle - 1) + requestsHistory.get(middle)) / 2;
        return List.of((double) http, (double) endpoints.size(), (double) errors4, (double) errors5,
                (double) failed, (double) sensitive, median, requestsHistory.isEmpty() ? 0.0 : 1.0);
    }
}
