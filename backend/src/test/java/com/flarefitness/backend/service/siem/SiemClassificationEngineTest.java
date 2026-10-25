package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import org.junit.jupiter.api.Test;

class SiemClassificationEngineTest {

    private final SiemClassificationEngine engine = new SiemClassificationEngine();

    @Test
    void lowSeverityDeclaredTestCanBePotentialNoise() {
        var result = engine.classify(input("low", 1, 1, true, false, false));

        assertThat(result.score()).isZero();
        assertThat(result.severity()).isEqualTo(IncidentSeverity.LOW);
        assertThat(result.classification()).isEqualTo(IncidentClassification.POTENTIAL_NOISE);
    }

    @Test
    void correlatedRulesPreventNoiseAndIncreaseScore() {
        var result = engine.classify(input("low", 3, 3, true, false, false));

        assertThat(result.score()).isEqualTo(55);
        assertThat(result.severity()).isEqualTo(IncidentSeverity.MEDIUM);
        assertThat(result.classification()).isEqualTo(IncidentClassification.INVESTIGATE);
    }

    @Test
    void highAndCriticalAreNeverNoise() {
        assertThat(engine.classify(input("high", 1, 1, true, false, false)).classification())
                .isEqualTo(IncidentClassification.INVESTIGATE);
        assertThat(engine.classify(input("critical", 1, 1, true, false, false)).classification())
                .isEqualTo(IncidentClassification.INVESTIGATE);
    }

    @Test
    void missingDataUsesUnknownBaselineAndCannotBecomeNoise() {
        var result = engine.classify(input(null, 1, 1, true, true, false));

        assertThat(result.score()).isEqualTo(50);
        assertThat(result.missingData()).isTrue();
        assertThat(result.classification()).isEqualTo(IncidentClassification.INVESTIGATE);
    }

    @Test
    void manualOverridePersistsInvestigateDecision() {
        var result = engine.classify(input("low", 1, 1, true, false, true));

        assertThat(result.classification()).isEqualTo(IncidentClassification.INVESTIGATE);
        assertThat(result.reasons()).anyMatch(reason -> reason.contains("override"));
    }

    @Test
    void scoresAreClampedToOneHundred() {
        var result = engine.classify(input("critical", 3, 3, false, false, false));

        assertThat(result.score()).isEqualTo(100);
        assertThat(result.severity()).isEqualTo(IncidentSeverity.URGENT);
    }

    private SiemClassificationEngine.ClassificationInput input(
            String severity,
            int rules,
            int alerts,
            boolean testWindow,
            boolean missingData,
            boolean override
    ) {
        return new SiemClassificationEngine.ClassificationInput(
                severity, rules, alerts, testWindow, missingData, override);
    }
}
