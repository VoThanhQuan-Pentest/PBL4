package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SessionEndpointSnapshotTest {
    private static final LocalDateTime START = LocalDateTime.of(2026, 10, 1, 0, 0);

    @Test void separateSnapshotPreservesSchema1Through3ScoresAndAllFrozenPrefixes() {
        for (int schema : new int[] {1, 2, 3}) {
            var row = row(); var vector = vector();
            score(row, schema);
            row.replaceSessionEndpointFeatures(vector, START.plusSeconds(1));
            assertThat(row.hasModelFeatures(4)).isTrue();
            assertThat(row.getSessionEndpointFeatureSchemaVersion()).isEqualTo(4);
            assertThat(row.modelFeatureVector(4)).isEqualTo(vector.values());
            assertThat(row.modelFeatureVector(4).subList(0, 25)).isEqualTo(row.modelFeatureVector(3));
            assertThat(row.modelFeatureVector(4).subList(0, 15)).isEqualTo(row.modelFeatureVector(2));
            assertThat(row.modelFeatureVector(4).subList(0, 11)).isEqualTo(row.modelFeatureVector(1));
            row.replaceSessionEndpointFeatures(changed(vector, 33, 30), START.plusSeconds(2));
            assertThat(row.getModelVersion()).isEqualTo("owned-model-v" + schema);
            assertThat(row.getScoredFeatureSchemaVersion()).isEqualTo(schema);
        }
    }

    @Test void identicalSchema4SnapshotKeepsItsScoreWhileChangedSchema4ClearsOnlyItsAssessment() {
        var row = row(); var vector = vector();
        row.replaceSessionEndpointFeatures(vector, START); score(row, 4);
        row.replaceSessionEndpointFeatures(vector, START.plusSeconds(1));
        assertThat(row.getModelVersion()).isEqualTo("owned-model-v4");
        row.replaceSessionEndpointFeatures(changed(vector, 33, 30), START.plusSeconds(2));
        assertThat(row.getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
        assertThat(row.getModelVersion()).isNull(); assertThat(row.getScoredFeatureSchemaVersion()).isNull();
        assertThat(row.getAnomalyPercentile()).isNull(); assertThat(row.getRiskScore()).isNull();
        assertThat(row.getRiskReasons()).isNull(); assertThat(row.getScoredAt()).isNull();
        assertThat(row.hasModelFeatures(4)).isTrue();
        assertThat(row.hasModelFeatures(3)).isTrue(); assertThat(row.hasModelFeatures(2)).isTrue();
    }

    @Test void upstreamRawPersonalOrContextualChangesInvalidateTheDependentSchema4SnapshotAndScore() {
        for (int upstream : new int[] {1, 2, 3}) {
            var row = row(); row.replaceSessionEndpointFeatures(vector(), START); score(row, 4);
            var values = new ArrayList<>(row.modelFeatureVector(upstream));
            int changedIndex = upstream == 1 ? 0 : upstream == 2 ? 11 : 16;
            values.set(changedIndex, values.get(changedIndex) + 1);
            var replacement = new AccountBehaviorFeatures.Vector(upstream, values);
            if (upstream == 1) row.replaceFeatures(replacement, 3, false, "203.0.113.1", "OTHER", "REAL", START.plusSeconds(1));
            if (upstream == 2) row.replacePersonalFeatures(replacement, START.plusSeconds(1));
            if (upstream == 3) row.replaceContextualFeatures(replacement, START.plusSeconds(1));
            assertThat(row.hasModelFeatures(4)).isFalse();
            assertThat(row.getSessionEndpointFeatureSchemaVersion()).isNull();
            assertThat(row.getModelVersion()).isNull(); assertThat(row.getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
        }
    }

    @Test void schema4RequiresAnExistingExactSchema3PrefixAndCannotInventLegacySnapshots() {
        var row = row();
        assertThat(row.hasModelFeatures(4)).isFalse();
        assertThatThrownBy(() -> row.modelFeatureVector(4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> row.replaceSessionEndpointFeatures(changed(vector(), 16, 99), START))
                .isInstanceOf(IllegalArgumentException.class);
        var rawOnly = new SiemAccountBehaviorWindow(); rawOnly.replaceFeatures(vector().base(), 2, false, null, null, "REAL", START);
        assertThatThrownBy(() -> rawOnly.replaceSessionEndpointFeatures(vector(), START)).isInstanceOf(IllegalArgumentException.class);
    }

    private static SiemAccountBehaviorWindow row() {
        var row = new SiemAccountBehaviorWindow(); var vector = vector();
        row.replaceFeatures(vector.base(), 2, false, "203.0.113.1", "OTHER", "REAL", START);
        row.replacePersonalFeatures(new AccountBehaviorFeatures.Vector(2, vector.values().subList(0, 15)), START);
        row.replaceContextualFeatures(new AccountBehaviorFeatures.Vector(3, vector.values().subList(0, 25)), START);
        return row;
    }

    private static AccountBehaviorFeatures.Vector vector() {
        return SessionEndpointBehaviorFeaturesTest.features(List.of(
                SessionEndpointBehaviorFeaturesTest.request(0, "PRODUCT_LIST", "GET", "a".repeat(64)),
                SessionEndpointBehaviorFeaturesTest.request(1, "PRODUCT_DETAIL", "GET", "a".repeat(64))));
    }

    private static AccountBehaviorFeatures.Vector changed(AccountBehaviorFeatures.Vector vector, int index, double value) {
        var values = new ArrayList<>(vector.values()); values.set(index, value);
        return new AccountBehaviorFeatures.Vector(vector.featureSchemaVersion(), values);
    }

    private static void score(SiemAccountBehaviorWindow row, int schema) {
        row.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment("owned-model-v" + schema,
                97.0, 12, "test-only model assessment", schema), START);
    }
}
