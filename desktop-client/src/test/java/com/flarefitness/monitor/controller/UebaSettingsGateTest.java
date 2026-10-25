package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import com.flarefitness.monitor.model.SiemModels;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class UebaSettingsGateTest {
    @Test void completedTrainingAloneNeverEnablesActivation() {
        assertFalse(job("SUCCEEDED", "NOT_RUN", "NOT_RUN", Map.of()).canActivate());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "FAIL", Map.of()).canActivate());
        assertFalse(job("SUCCEEDED", "RUNNING", "PASS", Map.of()).canActivate());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "PASS", Map.of()).canActivate());
        assertFalse(job("RETIRED", "SUCCEEDED", "PASS", Map.of()).canActivate());
        assertFalse(job("ACTIVE", "SUCCEEDED", "PASS", Map.of()).canActivate());
    }

    @Test void metricsStayModelOnlyAndUndefinedPrecisionIsNotRenderedAsPerfectAccuracy() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("recall", 0.0); metrics.put("false_positive_rate", 0.0); metrics.put("precision", null);
        metrics.put("tp", 0); metrics.put("fp", 0); metrics.put("tn", 10000); metrics.put("fn", 1000);
        metrics.put("normal_samples", 10000); metrics.put("positive_samples", 1000);
        String text = DashboardController.modelMetrics(job("SUCCEEDED", "SUCCEEDED", "FAIL", metrics));
        assertTrue(text.contains("MODEL ONLY"));
        assertTrue(text.contains("precision undefined"));
        assertFalse(text.contains("100.00%"));
    }

    @Test void strictActivationNeedsRealShadowAndDisplaysScopesSeparately() {
        Map<String, Object> counts = Map.of("tp", 10000, "fn", 0, "fp", 5, "tn", 9999995, "quality_gate", "PASS",
                "confidence", Map.of("conservative", Map.of("precision", Map.of("available", true, "lower", 0.998, "upper", 1.0),
                        "recall", Map.of("available", true, "lower", 0.999, "upper", 1.0),
                        "false_positive_rate", Map.of("available", true, "lower", 0.0, "upper", 0.000002))));
        Map<String, Object> summary = new HashMap<>(); summary.put("scopes", Map.of("MODEL_ONLY", counts, "SIEM_FINAL", counts));
        assertTrue(job("SUCCEEDED", "SUCCEEDED", "PASS", summary).canStartShadow());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "PASS", summary).canActivate());
        String text = DashboardController.modelMetrics(job("SUCCEEDED", "SUCCEEDED", "PASS", summary));
        assertTrue(text.contains("MODEL ONLY")); assertTrue(text.contains("SIEM FINAL"));
        assertTrue(text.contains("false-positive rate 0.00005%")); assertTrue(text.contains("[99.80000%, 100.00000%]"));
        summary.put("shadow_gate", "PASS"); assertTrue(job("SUCCEEDED", "SUCCEEDED", "PASS", summary).canActivate());
        summary.put("shadow_gate", "FAIL"); assertFalse(job("SUCCEEDED", "SUCCEEDED", "PASS", summary).canActivate());
    }

    @Test void corruptCountersCannotBeDisplayedAsAPerfectResult() {
        String text = DashboardController.modelMetrics(job("SUCCEEDED", "SUCCEEDED", "PASS", Map.of("tp", -1, "fn", 0, "fp", 0, "tn", 100)));
        assertTrue(text.startsWith("Invalid evaluation")); assertFalse(text.contains("100."));
    }

    @Test void contextualCandidatesUseTheSameQualityAndShadowGates() {
        Map<String, Object> counts = Map.of("tp", 10000, "fn", 0, "fp", 5, "tn", 9999995, "quality_gate", "PASS",
                "confidence", Map.of("conservative", Map.of("precision", Map.of("available", true, "lower", 0.998, "upper", 1.0),
                        "recall", Map.of("available", true, "lower", 0.999, "upper", 1.0),
                        "false_positive_rate", Map.of("available", true, "lower", 0.0, "upper", 0.000002))));
        Map<String, Object> summary = new HashMap<>(); summary.put("scopes", Map.of("MODEL_ONLY", counts, "SIEM_FINAL", counts));
        assertTrue(job("SUCCEEDED", "SUCCEEDED", "PASS", summary, 3).canStartShadow());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "PASS", summary, 3).canActivate());
        summary.put("shadow_gate", "PASS");
        assertTrue(job("SUCCEEDED", "SUCCEEDED", "PASS", summary, 3).canActivate());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "FAIL", summary, 3).canActivate());
        assertTrue(job("SUCCEEDED", "SUCCEEDED", "PASS", summary, 4).canActivate());
        assertFalse(job("SUCCEEDED", "SUCCEEDED", "PASS", Map.of("shadow_gate", "PASS"), 3).canStartShadow());
    }

    private static SiemModels.UebaTrainingJob job(String status, String evaluation, String gate, Map<String,Object> metrics) {
        return job(status, evaluation, gate, metrics, 2);
    }

    private static SiemModels.UebaTrainingJob job(String status, String evaluation, String gate, Map<String,Object> metrics, int schema) {
        return new SiemModels.UebaTrainingJob("job-test-1234", "model-test-1234", status, "DEMO_ONLY", 46600, 5400,
                LocalDateTime.now(), null, schema, "recipe-test-1234", "dataset-test-1234", evaluation, gate, metrics);
    }
}
