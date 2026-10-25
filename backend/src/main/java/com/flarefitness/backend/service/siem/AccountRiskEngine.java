package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.IncidentSeverity;
import java.util.ArrayList;
import java.util.List;

/** Transparent rule contributions; the Isolation Forest percentile is not a fraud probability. */
public final class AccountRiskEngine {
    private AccountRiskEngine() { }

    public static Assessment assess(AccountBehaviorFeatures.Vector features,
                                    SiemUebaGateway.Score modelScore, boolean baselineEstablished) {
        if (features == null || features.featureSchemaVersion() != AccountBehaviorFeatures.SCHEMA_VERSION) {
            throw new IllegalArgumentException("Incompatible behavior features.");
        }
        List<Double> values = features.values();
        int risk = 0;
        int signals = 0;
        int modelContribution = 0;
        boolean strictPolicy = modelScore != null && modelScore.policy() != null && modelScore.policy().strict();
        boolean independentDetection = strictPolicy && "VERY_UNUSUAL".equals(modelScore.level());
        List<String> reasons = new ArrayList<>();
        if (modelScore != null) {
            if (!Double.isFinite(modelScore.normalPercentile())
                    || modelScore.normalPercentile() < 0 || modelScore.normalPercentile() > 100) {
                throw new IllegalArgumentException("Invalid model percentile.");
            }
            if ("VERY_UNUSUAL".equals(modelScore.level())) {
                risk += 45;
                modelContribution = 45;
                signals++;
                reasons.add("Model marks the 15-minute activity as very unusual");
            } else if ("UNUSUAL".equals(modelScore.level())) {
                if (strictPolicy) reasons.add("Model warning below the frozen detection threshold: telemetry only");
                else {
                    risk += 25; modelContribution = 25;
                    signals++;
                    reasons.add("Model marks the 15-minute activity as unusual");
                }
            } else if (!"NORMAL_RANGE".equals(modelScore.level())) {
                throw new IllegalArgumentException("Invalid model level.");
            }
        }
        int failedLogins = values.get(3).intValue();
        if (failedLogins >= 5) {
            risk += 25;
            signals++;
            reasons.add("At least five failed logins in fifteen minutes");
        } else if (failedLogins >= 3) {
            risk += 15;
            signals++;
            reasons.add("At least three failed logins in fifteen minutes");
        }
        int clientErrors = values.get(1).intValue();
        if (clientErrors >= 10) {
            risk += 15;
            signals++;
            reasons.add("At least ten HTTP client errors");
        } else if (clientErrors >= 5) {
            risk += 10;
            signals++;
            reasons.add("At least five HTTP client errors");
        }
        if (values.get(2) >= 3) {
            risk += 10;
            signals++;
            reasons.add("At least three HTTP server errors");
        }
        if (baselineEstablished && values.get(8) == 1.0) {
            risk += 10;
            signals++;
            reasons.add("Source IP was not seen in the account baseline");
        }
        if (baselineEstablished && values.get(9) == 1.0) {
            risk += 8;
            signals++;
            reasons.add("User-agent family was not seen in the account baseline");
        }
        if (baselineEstablished && values.get(10) == 1.0) {
            risk += 8;
            signals++;
            reasons.add("Activity hour is unusual for this account");
        }
        if (values.get(5) >= 1) {
            risk += 12;
            signals++;
            reasons.add("Sensitive account action was performed");
        }
        if (values.get(0) >= 120) {
            risk += 15;
            signals++;
            reasons.add("At least 120 API requests in fifteen minutes");
        } else if (values.get(0) >= 60) {
            risk += 8;
            signals++;
            reasons.add("At least 60 API requests in fifteen minutes");
        }
        risk = Math.min(100, risk);
        IncidentSeverity severity = risk >= 85 ? IncidentSeverity.URGENT
                : risk >= 70 ? IncidentSeverity.HIGH
                : risk >= 50 ? IncidentSeverity.MEDIUM : IncidentSeverity.LOW;
        // Rule-only fallback uses a lower threshold but still requires corroboration.
        int threshold = modelScore == null ? 45 : 60;
        boolean createIncident = signals >= 2 && risk >= threshold;
        if (strictPolicy) {
            int ruleRisk = Math.max(0, risk - modelContribution);
            int ruleSignals = signals - (modelContribution > 0 ? 1 : 0);
            createIncident = independentDetection || ruleSignals >= 2 && ruleRisk >= modelScore.policy().ruleThreshold();
            if (independentDetection) {
                reasons.add("Independent strict-policy ML detection creates a human-reviewed L1 case, not automatic containment");
                if (!baselineEstablished) reasons.add("GLOBAL_PROXY: account baseline is insufficient; this is not a personalized compromise verdict");
            }
        }
        return new Assessment(risk, severity, createIncident,
                modelScore != null, List.copyOf(reasons));
    }

    public record Assessment(int riskScore, IncidentSeverity severity, boolean createIncident,
                             boolean modelAvailable, List<String> reasons) { }
}
