package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class PersonalBehaviorFeaturesTest {
    private static final LocalDateTime AT = LocalDateTime.of(2026, 9, 30, 12, 0);
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    @Test
    void sameRequestCountHasDifferentDeviationForQuietAndBusyAccounts() {
        var quiet = history(30, 9);
        var busy = history(30, 99);
        var base = new AccountBehaviorFeatures.Vector(1,
                List.of(99.0, 3.0, 1.0, 2.0, 3.0, 1.0, 3.0, 1.0, 0.0, 0.0, 0.0));
        var personal = AccountBehaviorFeatures.withPersonalFeatures(base, quiet);
        assertThat(personal.featureSchemaVersion()).isEqualTo(2);
        assertThat(personal.base()).isEqualTo(base);
        assertThat(personal.values()).hasSize(15);
        assertThat(personal.values().get(11)).isCloseTo(Math.log(10) / 0.25, within(1e-12));
        assertThat(AccountBehaviorFeatures.withPersonalFeatures(base, busy).values().get(11)).isZero();
        assertThat(personal.values().get(13)).isCloseTo(3.0 / 99, within(1e-12));
        assertThat(personal.values().get(14)).isEqualTo(0.4);
    }

    @Test
    void insufficientHistoryAndZeroDenominatorsNeverManufacturePersonalAnomalies() {
        var base = new AccountBehaviorFeatures.Vector(1,
                List.of(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0));
        assertThat(AccountBehaviorFeatures.withPersonalFeatures(base, history(29, 9)).values().subList(11, 15))
                .containsExactly(0.0, 0.0, 0.0, 0.0);
    }

    @Test
    void persistedSnapshotPreservesLegacyProjectionAndRecordsActualScoringSchema() {
        var row = window(99, 1);
        var personal = AccountBehaviorFeatures.withPersonalFeatures(new AccountBehaviorFeatures.Vector(1, row.featureVector()), history(30, 9));
        row.replacePersonalFeatures(personal, AT);
        assertThat(row.modelFeatureVector(2)).containsExactlyElementsOf(personal.values());
        assertThat(row.modelFeatureVector(1)).hasSize(11);
        row.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment("model-owned-v2", 99.5, 25,
                "Model is not proof of compromise", 2), AT);
        row.replacePersonalFeatures(personal, AT.plusSeconds(1));
        assertThat(row.getModelVersion()).isEqualTo("model-owned-v2");
        assertThat(row.getScoredFeatureSchemaVersion()).isEqualTo(2);
        assertThatThrownBy(() -> row.modelFeatureVector(3)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSnapshotCannotBeAttachedToDifferentRawEvidence() {
        var row = window(9, 1);
        var base = new AccountBehaviorFeatures.Vector(1, window(99, 2).featureVector());
        assertThatThrownBy(() -> row.replacePersonalFeatures(AccountBehaviorFeatures.withPersonalFeatures(base, history(30, 9)), AT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static AccountBaselinePolicy.Snapshot history(int count, int requests) {
        return AccountBaselinePolicy.summarize(IntStream.range(0, count).mapToObj(index -> window(requests, index)).toList(), AT, ZONE);
    }

    private static SiemAccountBehaviorWindow window(int requests, int index) {
        var row = new SiemAccountBehaviorWindow();
        row.setId("personal-fixture-" + index);
        row.setAccountId("personal-owned");
        row.setWindowStart(AT.minusDays(2).plusMinutes(index * 15L));
        row.setWindowEnd(row.getWindowStart().plusMinutes(15));
        row.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                List.of((double) requests, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0)),
                requests + 1, false, "198.51.100.1", "CHROMIUM", "NORMAL", AT);
        return row;
    }
}
