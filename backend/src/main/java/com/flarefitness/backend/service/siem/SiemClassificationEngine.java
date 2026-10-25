package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class SiemClassificationEngine {

    public ClassificationResult classify(ClassificationInput input) {
        String normalizedSeverity = normalize(input.sourceSeverity());
        boolean missingData = input.missingRequiredFields() || normalizedSeverity.isBlank();
        int score = baseline(normalizedSeverity);
        List<String> reasons = new ArrayList<>();
        reasons.add("Baseline " + score + " from source severity "
                + (normalizedSeverity.isBlank() ? "unknown" : normalizedSeverity));

        if (input.distinctRuleCountInTenMinutes() >= 3) {
            score += 25;
            reasons.add("+25: at least three distinct rules for the same source and service in ten minutes");
        } else if (input.distinctRuleCountInTenMinutes() >= 2) {
            score += 15;
            reasons.add("+15: at least two distinct rules for the same source and service in ten minutes");
        }

        if (input.uniqueAlertCount() >= 3) {
            score += 10;
            reasons.add("+10: at least three unique alerts in the incident");
        }

        boolean sourceAllowsNoiseReduction = "low".equals(normalizedSeverity)
                || "medium".equals(normalizedSeverity);
        boolean canReduceForTest = input.inDeclaredTestWindow()
                && sourceAllowsNoiseReduction
                && !missingData
                && input.distinctRuleCountInTenMinutes() < 2;
        if (canReduceForTest) {
            score -= 25;
            reasons.add("-25: expected activity inside a declared test window");
        }

        score = Math.max(0, Math.min(100, score));
        IncidentSeverity severity = scoreToSeverity(score);
        boolean potentialNoise = canReduceForTest
                && score < 30
                && !input.manualInvestigateOverride();
        IncidentClassification classification = potentialNoise
                ? IncidentClassification.POTENTIAL_NOISE
                : IncidentClassification.INVESTIGATE;

        if (input.manualInvestigateOverride()) {
            reasons.add("Manual analyst override: investigate");
        }
        if (missingData) {
            reasons.add("Missing-data safeguard: incident cannot be classified as noise");
        }
        if ("high".equals(normalizedSeverity) || "critical".equals(normalizedSeverity)) {
            classification = IncidentClassification.INVESTIGATE;
        }

        return new ClassificationResult(score, severity, classification, missingData, List.copyOf(reasons));
    }

    private int baseline(String severity) {
        return switch (severity) {
            case "low" -> 20;
            case "medium" -> 40;
            case "high" -> 65;
            case "critical" -> 85;
            default -> 50;
        };
    }

    private IncidentSeverity scoreToSeverity(int score) {
        if (score >= 80) {
            return IncidentSeverity.URGENT;
        }
        if (score >= 60) {
            return IncidentSeverity.HIGH;
        }
        if (score >= 30) {
            return IncidentSeverity.MEDIUM;
        }
        return IncidentSeverity.LOW;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    public record ClassificationInput(
            String sourceSeverity,
            int distinctRuleCountInTenMinutes,
            int uniqueAlertCount,
            boolean inDeclaredTestWindow,
            boolean missingRequiredFields,
            boolean manualInvestigateOverride
    ) {
    }

    public record ClassificationResult(
            int score,
            IncidentSeverity severity,
            IncidentClassification classification,
            boolean missingData,
            List<String> reasons
    ) {
    }
}
