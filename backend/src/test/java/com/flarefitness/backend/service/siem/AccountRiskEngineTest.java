package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.siem.IncidentSeverity;
import java.util.List;
import org.junit.jupiter.api.Test;

class AccountRiskEngineTest {
    @Test
    void newIpAloneNeverCreatesAnIncident() {
        AccountRiskEngine.Assessment result = AccountRiskEngine.assess(vector(
                0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0), null, true);
        assertThat(result.createIncident()).isFalse();
        assertThat(result.riskScore()).isEqualTo(10);
    }

    @Test
    void modelPlusIndependentLoginBurstRaisesL1Case() {
        AccountRiskEngine.Assessment result = AccountRiskEngine.assess(vector(
                0, 0, 0, 6, 1, 0, 0, 1, 0, 0, 0),
                new SiemUebaGateway.Score(0.7, 99.95, "VERY_UNUSUAL"), true);
        assertThat(result.createIncident()).isTrue();
        assertThat(result.riskScore()).isEqualTo(70);
        assertThat(result.severity()).isEqualTo(IncidentSeverity.HIGH);
        assertThat(result.reasons()).hasSize(2);
    }

    @Test
    void ruleOnlyFallbackCanDetectCorroboratedAbuse() {
        AccountRiskEngine.Assessment result = AccountRiskEngine.assess(vector(
                130, 11, 0, 6, 0, 0, 2, 1, 0, 0, 0), null, false);
        assertThat(result.modelAvailable()).isFalse();
        assertThat(result.createIncident()).isTrue();
        assertThat(result.riskScore()).isEqualTo(55);
    }

    private AccountBehaviorFeatures.Vector vector(double... values) {
        return new AccountBehaviorFeatures.Vector(1, java.util.Arrays.stream(values).boxed().toList());
    }
}
