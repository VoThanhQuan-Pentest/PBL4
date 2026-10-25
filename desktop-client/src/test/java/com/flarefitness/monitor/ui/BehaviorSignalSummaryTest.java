package com.flarefitness.monitor.ui;

import static org.junit.jupiter.api.Assertions.*;

import com.flarefitness.monitor.model.SiemModels;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class BehaviorSignalSummaryTest {
    @Test void serverErrorsArePossibleOperationalFaultsNotAttackConfirmation() {
        String text = BehaviorSignalSummary.describe(window(Map.of("http_5xx_count", 25.0), true));
        assertTrue(text.startsWith("Service-error signal (possible operational fault)"));
        assertTrue(text.contains("HTTP 5xx observed"));
        assertTrue(text.contains("not attack confirmation"));
        assertFalse(text.contains("Security-context signal"));
        assertFalse(text.contains("CONFIRMED_ATTACK"));
    }

    @Test void failedLoginsAndBaselineSourceChangesAreSecurityContextOnly() {
        for (String name : List.of("failed_login_count", "new_ip_flag", "new_user_agent_flag")) {
            String text = BehaviorSignalSummary.describe(window(Map.of(name, 1.0), true));
            assertTrue(text.startsWith("Security-context signal (needs investigation)"));
            assertTrue(text.contains("not attack confirmation"));
        }
    }

    @Test void serviceAndSecuritySignalsRemainSeparateWhenBothArePresent() {
        String text = BehaviorSignalSummary.describe(window(Map.of("http_5xx_count", 3.0,
                "failed_login_count", 2.0, "new_ip_flag", 1.0), true));
        assertTrue(text.startsWith("Mixed service-error and security-context signals"));
        assertTrue(text.contains("HTTP 5xx observed"));
        assertTrue(text.contains("Failed logins observed"));
        assertTrue(text.contains("established baseline"));
    }

    @Test void sourceFlagsWithoutAnEstablishedBaselineDoNotFabricateSuspicion() {
        assertTrue(BehaviorSignalSummary.describe(window(Map.of("new_ip_flag", 1.0,
                "new_user_agent_flag", 1.0), false)).startsWith("Cause undetermined"));
    }

    @Test void scoresReasonsLabelsAndOrdinarySensitiveActionsDoNotDetermineCause() {
        assertTrue(BehaviorSignalSummary.describe(window(Map.of("http_4xx_count", 50.0,
                "sensitive_action_count", 8.0, "unusual_hour_flag", 1.0), true))
                .startsWith("Cause undetermined"));
    }

    @Test void retainedHttp503CanProvideServiceContextWhenWindowCountersAreMissing() {
        String text = BehaviorSignalSummary.describe(List.of(), List.of(event("HTTP_REQUEST", "REQUEST", "FAILURE", 503)));
        assertTrue(text.startsWith("Service-error signal"));
        assertFalse(text.contains("Failed logins observed"));
    }

    @Test void onlyTypedLoginFailureProvidesAuthenticationContext() {
        String text = BehaviorSignalSummary.describe(List.of(), List.of(event("AUTH", "LOGIN", "FAILURE", null)));
        assertTrue(text.startsWith("Security-context signal"));
        assertTrue(BehaviorSignalSummary.describe(List.of(), List.of(
                event("DOMAIN_ACTION", "PASSWORD_CHANGE", "FAILURE", null),
                event("HTTP_REQUEST", "REQUEST", "FAILURE", 401),
                event("HTTP_REQUEST", "REQUEST", "FAILURE", 600)))
                .startsWith("Cause undetermined"));
    }

    @Test void missingOrInvalidTelemetryIsUndeterminedRatherThanSafeOrMalicious() {
        assertTrue(BehaviorSignalSummary.describe(null, null).startsWith("Cause undetermined"));
        assertTrue(BehaviorSignalSummary.describe(window(null, true)).startsWith("Cause undetermined"));
        for (double value : new double[]{0, -1, 0.5, Double.NaN, Double.POSITIVE_INFINITY}) {
            assertTrue(BehaviorSignalSummary.describe(window(Map.of("http_5xx_count", value,
                    "failed_login_count", value), true)).startsWith("Cause undetermined"));
        }
        assertTrue(BehaviorSignalSummary.describe(window(Map.of("new_ip_flag", 2.0), true))
                .startsWith("Cause undetermined"));
    }

    private static SiemModels.BehaviorWindow window(Map<String, Double> features, boolean baseline) {
        // High model risk and fixture labels must not become an attack verdict.
        return new SiemModels.BehaviorWindow("window-1", "account-1", null, null, 100, baseline,
                features, "203.0.113.20", "Other", "ABNORMAL", "SCORED_MODEL", "model-1",
                99.9, 100, "CONFIRMED_ATTACK", 4, 4);
    }

    private static SiemModels.SecurityEventEvidence event(String type, String action, String outcome, Integer status) {
        return new SiemModels.SecurityEventEvidence("event-1", null, type, action, outcome,
                "203.0.113.20", "auth", status, "Other", "trace-1", "ABNORMAL");
    }
}
