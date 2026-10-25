package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class ContextualBehaviorFeaturesTest {
    private static final LocalDateTime START = LocalDateTime.of(2026, 4, 1, 0, 0);
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");
    private static final AccountBaselinePolicy.Snapshot COLD = AccountBaselinePolicy.summarize(List.of(), START, ZONE);

    @Test void preservesSchema2AndAddsObservableTimingThatCountsCannotDistinguish() {
        List<SiemSecurityEvent> slow = new ArrayList<>(), burst = new ArrayList<>();
        for (int index = 0; index < 40; index++) {
            slow.add(request(index * 10, 200, "products")); burst.add(request(index / 10, 200, "products"));
        }
        var oldSlow = personal(slow); var oldBurst = personal(burst);
        assertThat(oldSlow.values()).isEqualTo(oldBurst.values());
        var first = ContextualBehaviorFeatures.fromEvents(oldSlow, COLD, slow);
        var second = ContextualBehaviorFeatures.fromEvents(oldBurst, COLD, burst);
        assertThat(first.featureSchemaVersion()).isEqualTo(3); assertThat(first.values()).hasSize(25);
        assertThat(first.values().subList(0, 15)).isEqualTo(oldSlow.values());
        assertThat(first.values().get(15)).isEqualTo(1); assertThat(second.values().get(15)).isEqualTo(40);
        assertThat(first.values().get(16)).isEqualTo(10); assertThat(second.values().get(16)).isZero();
        assertThat(first.values().subList(20, 22)).containsExactly(0.0, 0.0);
    }

    @Test void labelIdentityAndInputOrderDoNotDetermineFeatures() {
        var events = new ArrayList<>(List.of(request(0, 403, "orders"), request(1, 403, "profile"), request(2, 200, "profile")));
        var expected = ContextualBehaviorFeatures.fromEvents(personal(events), COLD, events);
        events.forEach(event -> { event.setId("ignored-id"); event.setActorUserId("ignored-account"); event.setDemoLabel("ABNORMAL"); });
        Collections.reverse(events);
        assertThat(ContextualBehaviorFeatures.fromEvents(personal(events), COLD, events).values()).isEqualTo(expected.values());
        assertThat(expected.values().get(18)).isEqualTo(1); assertThat(expected.values().get(19)).isEqualTo(0.5);
        assertThat(expected.values().get(24)).isEqualTo(2);
    }

    @Test void simultaneousMixedStatusesDoNotInventAnErrorSequence() {
        var events = List.of(request(0, 403, "orders"), request(0, 200, "profile"), request(1, 403, "profile"));
        var values = ContextualBehaviorFeatures.fromEvents(personal(events), COLD, events).values();
        assertThat(values.get(24)).isEqualTo(1); assertThat(values.get(15)).isEqualTo(3);
    }

    @Test void sourceCountsAndMissingTimestampsCannotMasqueradeAsCompatibleSnapshots() {
        var events = List.of(request(0, 200, "products"));
        assertThatThrownBy(() -> ContextualBehaviorFeatures.fromEvents(personal(events), COLD, List.of())).isInstanceOf(IllegalArgumentException.class);
        var bad = request(0, 200, "products"); bad.setEventTimestamp(null);
        assertThatThrownBy(() -> ContextualBehaviorFeatures.fromEvents(personal(events), COLD, List.of(bad))).isInstanceOf(IllegalArgumentException.class);
        var outside = List.of(request(0, 200, "products"), request(900, 200, "products"));
        assertThatThrownBy(() -> ContextualBehaviorFeatures.fromEvents(personal(outside), COLD, outside)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void versionedPersistenceKeepsExistingLegacyScoresAndInvalidatesOnlyChangedV3Scores() {
        var events = List.of(request(0, 200, "products"), request(20, 200, "profile"));
        var personal = personal(events); var contextual = ContextualBehaviorFeatures.fromEvents(personal, COLD, events);
        var row = new SiemAccountBehaviorWindow(); row.replaceFeatures(personal.base(), 2, false, "203.0.113.1", "OTHER", "REAL", START);
        row.replacePersonalFeatures(personal, START);
        row.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment("owned-model-v2", 97.0, 0, "normal", 2), START);
        row.replaceContextualFeatures(contextual, START.plusSeconds(1));
        assertThat(row.modelFeatureVector(1)).isEqualTo(personal.base().values());
        assertThat(row.modelFeatureVector(2)).isEqualTo(personal.values());
        assertThat(row.modelFeatureVector(3)).isEqualTo(contextual.values());
        assertThat(row.getModelVersion()).isEqualTo("owned-model-v2");
        row.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment("owned-model-v3", 97.0, 0, "normal", 3), START);
        row.replaceContextualFeatures(contextual, START.plusSeconds(2));
        assertThat(row.getModelVersion()).isEqualTo("owned-model-v3");
        var faster = List.of(request(0, 200, "products"), request(1, 200, "profile"));
        row.replaceContextualFeatures(ContextualBehaviorFeatures.fromEvents(personal, COLD, faster), START.plusSeconds(3));
        assertThat(row.getModelVersion()).isNull(); assertThat(row.getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
    }

    private static AccountBehaviorFeatures.Vector personal(List<SiemSecurityEvent> events) {
        return AccountBehaviorFeatures.withPersonalFeatures(AccountBehaviorFeatures.fromEvents(events, COLD.features(), ZONE), COLD);
    }
    private static SiemSecurityEvent request(int seconds, int status, String group) {
        var event = new SiemSecurityEvent(); event.setEventTimestamp(START.plusSeconds(seconds)); event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST"); event.setHttpStatus(status); event.setRouteGroup(group); event.setSourceIp("203.0.113.1");
        return event;
    }
}
