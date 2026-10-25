package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Research representation v1 at a server-observed sensitive attempt, before its
 * outcome or account mutation. This is not a serving schema or a blocking policy.
 * Schema 4 and its 37 dimensions remain unchanged. IDs are association keys only.
 */
public final class PostLoginBehaviorFeatures {
    public static final String VERSION = "postlogin-before-action-v1";
    public static final int MAXIMUM_CONTEXT_EVENTS = 10_000;
    public static final List<String> NAMES = List.of(
            "current_operation_password_change", "current_operation_email_change",
            "authenticated_session_covered", "same_session_successful_login_observed",
            "session_age_seconds", "seconds_since_observed_login",
            "prior_sensitive_attempts_same_session_15m", "prior_sensitive_successes_same_session_15m",
            "prior_password_changes_same_session_15m", "prior_email_changes_same_session_15m",
            "prior_http_requests_same_session_15m", "prior_http_4xx_same_session_15m",
            "prior_http_5xx_same_session_15m", "prior_profile_reads_same_session_15m",
            "other_authenticated_sessions_account_15m", "unassociated_sensitive_actions_account_15m",
            "prior_password_resets_for_account_15m", "previous_attempt_password_change",
            "previous_attempt_email_change", "seconds_since_previous_attempt");
    private static final Set<String> SENSITIVE = Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE");

    private PostLoginBehaviorFeatures() { }

    public static Snapshot beforeAttempt(SiemSecurityEvent attempt, List<SiemSecurityEvent> context) {
        if (attempt == null || context == null || context.size() > MAXIMUM_CONTEXT_EVENTS
                || !"SENSITIVE_ACTION_ATTEMPT".equals(attempt.getEventType())
                || !"ATTEMPT".equals(attempt.getOutcome()) || !sensitive(attempt)
                || attempt.getActorUserId() == null || attempt.getActorUserId().isBlank()
                || attempt.getEventTimestamp() == null || context.stream().anyMatch(e -> e == null || e.getEventTimestamp() == null)) {
            throw new IllegalArgumentException("Bounded server-sensitive attempt and timestamped context required.");
        }
        String account = attempt.getActorUserId();
        LocalDateTime asOf = attempt.getEventTimestamp();
        boolean covered = validSession(attempt);
        LocalDateTime login = null, previousAttempt = null;
        String previousAction = null;
        boolean previousTied = false;
        int attempts = 0, successes = 0, passwords = 0, emails = 0, requests = 0;
        int clientErrors = 0, serverErrors = 0, profileReads = 0, unassociated = 0, resets = 0;
        Set<String> otherSessions = new HashSet<>(), eventIds = new HashSet<>();
        for (SiemSecurityEvent event : context) {
            if (!event.getEventTimestamp().isBefore(asOf)) continue; // No outcome/future leakage, including ties.
            if (event.getId() != null && !eventIds.add(event.getId())) {
                throw new IllegalArgumentException("Duplicate context event identity.");
            }
            boolean actor = account.equals(event.getActorUserId());
            boolean recent = event.getEventTimestamp().isAfter(asOf.minusMinutes(15));
            if (recent && "DOMAIN_ACTION".equals(event.getEventType()) && "PASSWORD_RESET".equals(event.getAction())
                    && (actor || event.getActorUserId() == null && account.equals(event.getTargetUserId()))) resets++;
            if (!actor) continue;
            boolean valid = validSession(event);
            boolean same = covered && valid && attempt.getSessionPseudonym().equals(event.getSessionPseudonym())
                    && attempt.getSessionIssuedAt().equals(event.getSessionIssuedAt());
            if (same && "AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction())
                    && "SUCCESS".equals(event.getOutcome()) && event.getEventTimestamp().isAfter(asOf.minusDays(1))
                    && (login == null || login.isBefore(event.getEventTimestamp()))) login = event.getEventTimestamp();
            if (!recent) continue;
            if (valid && (!covered || !attempt.getSessionPseudonym().equals(event.getSessionPseudonym()))) {
                otherSessions.add(event.getSessionPseudonym());
            }
            if ("DOMAIN_ACTION".equals(event.getEventType()) && sensitive(event) && !valid) unassociated++;
            if (!same) continue;
            if ("SENSITIVE_ACTION_ATTEMPT".equals(event.getEventType()) && "ATTEMPT".equals(event.getOutcome()) && sensitive(event)) {
                attempts++;
                if (previousAttempt == null || previousAttempt.isBefore(event.getEventTimestamp())) {
                    previousAttempt = event.getEventTimestamp(); previousAction = event.getAction(); previousTied = false;
                } else if (previousAttempt.equals(event.getEventTimestamp())) previousTied = true;
            } else if ("DOMAIN_ACTION".equals(event.getEventType()) && "SUCCESS".equals(event.getOutcome()) && sensitive(event)) {
                successes++;
                if ("PASSWORD_CHANGE".equals(event.getAction())) passwords++; else emails++;
            } else if ("HTTP_REQUEST".equals(event.getEventType())) {
                requests++;
                Integer status = event.getHttpStatus();
                if (status != null && status >= 400 && status < 500) clientErrors++;
                if (status != null && status >= 500 && status < 600) serverErrors++;
                if ("PROFILE_READ".equals(event.getEndpointCategory()) && status != null && status >= 200 && status < 300) profileReads++;
            }
        }
        List<Double> values = new ArrayList<>(List.of(
                "PASSWORD_CHANGE".equals(attempt.getAction()) ? 1.0 : 0.0,
                "EMAIL_CHANGE".equals(attempt.getAction()) ? 1.0 : 0.0,
                covered ? 1.0 : 0.0, login != null ? 1.0 : 0.0,
                covered ? seconds(attempt.getSessionIssuedAt(), asOf) : 0.0, login != null ? seconds(login, asOf) : 0.0,
                (double) attempts, (double) successes, (double) passwords, (double) emails,
                (double) requests, (double) clientErrors, (double) serverErrors, (double) profileReads,
                (double) otherSessions.size(), (double) unassociated, (double) resets,
                !previousTied && "PASSWORD_CHANGE".equals(previousAction) ? 1.0 : 0.0,
                !previousTied && "EMAIL_CHANGE".equals(previousAction) ? 1.0 : 0.0,
                previousAttempt != null && !previousTied ? seconds(previousAttempt, asOf) : 0.0));
        return new Snapshot(VERSION, NAMES, List.copyOf(values));
    }

    private static boolean sensitive(SiemSecurityEvent event) {
        return event.getAction() != null && SENSITIVE.contains(event.getAction());
    }

    private static boolean validSession(SiemSecurityEvent event) {
        boolean http = "HTTP_REQUEST".equals(event.getEventType()) && Integer.valueOf(3).equals(event.getTelemetryContractVersion());
        boolean postLogin = Integer.valueOf(4).equals(event.getTelemetryContractVersion())
                && (("AUTH".equals(event.getEventType()) && "LOGIN".equals(event.getAction()) && "SUCCESS".equals(event.getOutcome()))
                    || ("DOMAIN_ACTION".equals(event.getEventType()) && sensitive(event) && "SUCCESS".equals(event.getOutcome()))
                    || ("SENSITIVE_ACTION_ATTEMPT".equals(event.getEventType()) && sensitive(event) && "ATTEMPT".equals(event.getOutcome())));
        return (http || postLogin) && event.getActorUserId() != null && !event.getActorUserId().isBlank()
                && event.getSessionPseudonym() != null && event.getSessionPseudonym().matches("[0-9a-f]{64}")
                && event.getSessionIssuedAt() != null && !event.getSessionIssuedAt().isAfter(event.getEventTimestamp());
    }

    private static double seconds(LocalDateTime from, LocalDateTime to) {
        Duration duration = Duration.between(from, to);
        return Math.min(86400, duration.getSeconds() + duration.getNano() / 1_000_000_000.0);
    }

    public record Snapshot(String version, List<String> names, List<Double> values) { }
}
