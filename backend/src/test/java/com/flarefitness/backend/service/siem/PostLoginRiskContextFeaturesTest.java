package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PostLoginRiskContextFeaturesTest {
    SiemSecurityEvent attempt() {
        var e = new SiemSecurityEvent(); e.setActorUserId("owned-account");
        e.setEventType("SENSITIVE_ACTION_ATTEMPT"); e.setAction("EMAIL_CHANGE"); e.setOutcome("ATTEMPT");
        e.setEventTimestamp(LocalDateTime.of(2026, 8, 1, 0, 15, 5));
        e.setTelemetryContractVersion(4); e.setSessionPseudonym("a".repeat(64));
        e.setSessionIssuedAt(LocalDateTime.of(2026, 8, 1, 0, 14, 59)); return e;
    }
    SiemSecurityEvent failure(String id) {
        var e = new SiemSecurityEvent(); e.setId(id); e.setTargetUserId("owned-account");
        e.setEventType("AUTH"); e.setAction("LOGIN"); e.setOutcome("FAILURE");
        e.setEventTimestamp(LocalDateTime.of(2026, 8, 1, 0, 14, 30)); return e;
    }
    @Test void retainsAccountFailuresAcrossWindowAndSessionBoundaryWithoutInferringByIp() {
        var at = attempt(); var context = new ArrayList<SiemSecurityEvent>();
        for (int i = 0; i < 8; i++) context.add(failure("failure-" + i));
        var post = PostLoginBehaviorFeatures.beforeAttempt(at, context);
        assertThat(post.values().get(10)).isZero();
        assertThat(PostLoginRiskContextFeatures.fromObserved(at, context, List.of()).get(4)).isEqualTo(8);
        context.forEach(e -> e.setTargetUserId("unrelated-account"));
        assertThat(PostLoginRiskContextFeatures.fromObserved(at, context, List.of()).get(4)).isZero();
    }
    @Test void excludesFutureAndExactLowerBoundaryAndRejectsDuplicates() {
        var at = attempt(); var old = failure("old"); old.setEventTimestamp(at.getEventTimestamp().minusMinutes(15));
        var tied = failure("tied"); tied.setEventTimestamp(at.getEventTimestamp());
        assertThat(PostLoginRiskContextFeatures.fromObserved(at, List.of(old, tied), List.of()).get(4)).isZero();
        var duplicate = failure("duplicate");
        assertThatThrownBy(() -> PostLoginRiskContextFeatures.fromObserved(at, List.of(duplicate, duplicate), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
