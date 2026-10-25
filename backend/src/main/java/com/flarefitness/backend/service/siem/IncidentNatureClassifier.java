package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;

/**
 * Separates operational symptoms from security behavior without claiming an
 * ML anomaly is a confirmed attack. Only an activated prevention signature
 * produces SECURITY_DETECTION; analysts still record the final conclusion.
 */
public final class IncidentNatureClassifier {
    private IncidentNatureClassifier() { }

    public static IncidentNature fromUebaWindow(SiemAccountBehaviorWindow window) {
        if (window == null) throw new IllegalArgumentException("Server-owned UEBA window is required.");
        var features = window.featureVector();
        int requests = features.get(0).intValue();
        int clientErrors = features.get(1).intValue();
        int serverErrors = features.get(2).intValue();
        int failedLogins = features.get(3).intValue();
        int sensitiveActions = features.get(5).intValue();
        boolean securitySignals = clientErrors >= 5 || failedLogins >= 3
                || sensitiveActions >= 1 || requests >= 120;
        if (serverErrors >= 3 && securitySignals) return IncidentNature.MIXED_ANOMALY;
        if (serverErrors >= 3) return IncidentNature.OPERATIONAL_ANOMALY;
        return IncidentNature.ACCOUNT_BEHAVIOR_ANOMALY;
    }

    /** Exact locally managed Elastic rule identity; never infer an operational type from user text. */
    public static IncidentNature fromElasticRule(String ruleId) {
        return "flare-lab-server-errors".equals(ruleId)
                ? IncidentNature.OPERATIONAL_ANOMALY : IncidentNature.ELASTIC_DETECTION;
    }

    public static IncidentNature merge(IncidentNature existing, IncidentNature incoming) {
        if (incoming == null || incoming == IncidentNature.UNKNOWN) {
            return existing == null ? IncidentNature.UNKNOWN : existing;
        }
        if (existing == null || existing == IncidentNature.UNKNOWN) return incoming;
        if (existing == incoming) return existing;
        return IncidentNature.MIXED_ANOMALY;
    }
}
