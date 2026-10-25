package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class IncidentNatureClassifierTest {
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 12, 12, 0);

    @Test
    void repeatedFiveHundredErrorsAreOperationalNotAnAttackLabel() {
        assertThat(IncidentNatureClassifier.fromUebaWindow(window(20, 0, 8, 0, 0)))
                .isEqualTo(IncidentNature.OPERATIONAL_ANOMALY);
    }

    @Test
    void securitySignalsAndOperationalErrorsAreKeptAsMixedNotCollapsed() {
        assertThat(IncidentNatureClassifier.fromUebaWindow(window(20, 5, 8, 3, 0)))
                .isEqualTo(IncidentNature.MIXED_ANOMALY);
        assertThat(IncidentNatureClassifier.fromUebaWindow(window(20, 5, 0, 3, 0)))
                .isEqualTo(IncidentNature.ACCOUNT_BEHAVIOR_ANOMALY);
    }

    @Test
    void signatureEvidenceRemainsDistinctWhenMergedWithOperationalEvidence() {
        assertThat(IncidentNatureClassifier.merge(null, IncidentNature.SECURITY_DETECTION))
                .isEqualTo(IncidentNature.SECURITY_DETECTION);
        assertThat(IncidentNatureClassifier.merge(IncidentNature.SECURITY_DETECTION,
                IncidentNature.OPERATIONAL_ANOMALY)).isEqualTo(IncidentNature.MIXED_ANOMALY);
        assertThat(IncidentNatureClassifier.merge(IncidentNature.UNKNOWN,
                IncidentNature.OPERATIONAL_ANOMALY)).isEqualTo(IncidentNature.OPERATIONAL_ANOMALY);
    }

    @Test
    void onlyTheExactOwnedServerErrorRuleIsClassifiedAsOperational() {
        assertThat(IncidentNatureClassifier.fromElasticRule("flare-lab-server-errors"))
                .isEqualTo(IncidentNature.OPERATIONAL_ANOMALY);
        assertThat(IncidentNatureClassifier.fromElasticRule("flare-lab-auth-bruteforce"))
                .isEqualTo(IncidentNature.ELASTIC_DETECTION);
        assertThat(IncidentNatureClassifier.fromElasticRule("user supplied service error"))
                .isEqualTo(IncidentNature.ELASTIC_DETECTION);
    }

    private static SiemAccountBehaviorWindow window(int requests, int clientErrors, int serverErrors,
                                                     int failedLogins, int sensitiveActions) {
        var result = new SiemAccountBehaviorWindow();
        result.setId("nature-classifier-fixture");
        result.setWindowStart(NOW.minusMinutes(15));
        result.setWindowEnd(NOW);
        result.replaceFeatures(new AccountBehaviorFeatures.Vector(AccountBehaviorFeatures.SCHEMA_VERSION,
                List.of((double) requests, (double) clientErrors, (double) serverErrors,
                        (double) failedLogins, 0.0, (double) sensitiveActions,
                        (double) Math.min(requests, Math.max(clientErrors, 1)), 1.0, 0.0, 0.0, 0.0)),
                requests, false, "8.8.8.8", "FIREFOX", "REAL", NOW);
        return result;
    }
}
