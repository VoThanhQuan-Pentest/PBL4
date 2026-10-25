package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class PostLoginBehaviorFeaturesTest {
    private static final LocalDateTime START = LocalDateTime.of(2026, 8, 1, 0, 0);
    private static final String A = "a".repeat(64), B = "b".repeat(64);

    @Test void directAssociationSurvivesWindowBoundaryAndNeverJoinsOtherSessionsOrAccounts() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 901, A);
        var login = event("AUTH", "LOGIN", 899, A);
        attempt.setSessionIssuedAt(START.plusSeconds(899)); login.setSessionIssuedAt(START.plusSeconds(899));
        var foreignSession = event("DOMAIN_ACTION", "EMAIL_CHANGE", 900, B);
        var foreignAccount = event("DOMAIN_ACTION", "PASSWORD_CHANGE", 900, A); foreignAccount.setActorUserId("another-account");
        var values = features(attempt, List.of(login, foreignSession, foreignAccount));
        assertThat(values.subList(0, 6)).containsExactly(1.0, 0.0, 1.0, 1.0, 2.0, 2.0);
        assertThat(values.get(7)).isZero();
        assertThat(values.get(14)).isEqualTo(1);
        assertThat(features(attempt, List.of(event("AUTH", "LOGIN", 899, B))).get(3)).isZero();
    }

    @Test void actionTypeAndPrecedingSequenceRemainObservableWithoutUsingTheCurrentOutcome() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "EMAIL_CHANGE", 20, A);
        var prior = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 10, A);
        var success = event("DOMAIN_ACTION", "PASSWORD_CHANGE", 11, A);
        var values = features(attempt, List.of(prior, success));
        assertThat(values.subList(0, 2)).containsExactly(0.0, 1.0);
        assertThat(values.subList(6, 10)).containsExactly(1.0, 1.0, 1.0, 0.0);
        assertThat(values.subList(17, 20)).containsExactly(1.0, 0.0, 10.0);
        var future = event("DOMAIN_ACTION", "EMAIL_CHANGE", 21, A);
        var simultaneous = event("DOMAIN_ACTION", "EMAIL_CHANGE", 20, A);
        assertThat(features(attempt, List.of(prior, success, future, simultaneous, attempt))).isEqualTo(values);
        assertThat(features(event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 20, A), List.of(prior, success))).isNotEqualTo(values);
    }

    @Test void missingCoverageAndUnauthenticatedResetStayExplicitRatherThanBeingGuessed() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 20, A);
        var reset = event("DOMAIN_ACTION", "PASSWORD_RESET", 10, null);
        reset.setActorUserId(null); reset.setTargetUserId("owned-account");
        var missing = event("DOMAIN_ACTION", "EMAIL_CHANGE", 11, null);
        var values = features(attempt, List.of(reset, missing));
        assertThat(values.get(3)).isZero();
        assertThat(values.get(7)).isZero();
        assertThat(values.get(15)).isEqualTo(1);
        assertThat(values.get(16)).isEqualTo(1);
        attempt.setSessionPseudonym(null); attempt.setSessionIssuedAt(null);
        assertThat(features(attempt, List.of()).subList(2, 6)).containsOnly(0.0);
        assertThatThrownBy(() -> features(reset, List.of())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void identifiersLabelsInputOrderingAndHiddenIntentDoNotChangeTheVector() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 20, A);
        var context = new ArrayList<>(List.of(event("AUTH", "LOGIN", 1, A),
                event("SENSITIVE_ACTION_ATTEMPT", "EMAIL_CHANGE", 10, A)));
        var expected = features(attempt, context);
        for (var event : context) {
            event.setId("ignored-" + event.getEventTimestamp()); event.setTraceId("same-client-trace");
            event.setDemoLabel("ABNORMAL"); event.setActorUserId("renamed-account"); event.setSessionPseudonym(B);
        }
        attempt.setActorUserId("renamed-account"); attempt.setSessionPseudonym(B); attempt.setDemoLabel("NORMAL");
        Collections.reverse(context);
        assertThat(features(attempt, context)).isEqualTo(expected);
    }

    @Test void tiedAttemptsHaveNoInventedOrderAndDuplicateEventsCannotInflateCounts() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "EMAIL_CHANGE", 20, A);
        var a = event("SENSITIVE_ACTION_ATTEMPT", "EMAIL_CHANGE", 10, A);
        var b = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 10, A);
        assertThat(features(attempt, List.of(a, b)).subList(17, 20)).containsOnly(0.0);
        a.setId("same-event");
        assertThatThrownBy(() -> features(attempt, List.of(a, a))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void operationalRequestFailuresAndSuccessfulProfileReadsRemainSeparate() {
        var attempt = event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", 20, A);
        var good = event("HTTP_REQUEST", "API_REQUEST", 1, A); good.setHttpStatus(200); good.setEndpointCategory("PROFILE_READ");
        var failure = event("HTTP_REQUEST", "API_REQUEST", 2, A); failure.setHttpStatus(503);
        assertThat(features(attempt, List.of(good, failure)).subList(10, 14)).containsExactly(2.0, 0.0, 1.0, 1.0);
    }

    private static List<Double> features(SiemSecurityEvent attempt, List<SiemSecurityEvent> context) {
        var snapshot = PostLoginBehaviorFeatures.beforeAttempt(attempt, context);
        assertThat(snapshot.version()).isEqualTo("postlogin-before-action-v1");
        assertThat(snapshot.names()).hasSize(20);
        return snapshot.values();
    }

    private static SiemSecurityEvent event(String type, String action, int seconds, String session) {
        var value = new SiemSecurityEvent(); value.setEventType(type); value.setAction(action);
        value.setOutcome("SENSITIVE_ACTION_ATTEMPT".equals(type) ? "ATTEMPT" : "SUCCESS");
        value.setActorUserId("owned-account"); value.setTargetUserId("owned-account");
        value.setEventTimestamp(START.plusSeconds(seconds));
        value.setTelemetryContractVersion("HTTP_REQUEST".equals(type) ? 3 : 4);
        value.setSessionPseudonym(session); value.setSessionIssuedAt(session == null ? null : START);
        return value;
    }
}
