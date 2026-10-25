package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class ActionProofCapturePlanTest {
    @Test void protectedControlsSeparateActorRoleFromTheAvailabilityOfProof() {
        var plans = ActionProofCapturePlan.coverageControls();
        assertThat(plans).hasSize(4);
        var pairs = plans.stream().collect(Collectors.groupingBy(ActionProofCapturePlan.Plan::pairId));
        assertThat(pairs).hasSize(2);
        for (var pair : pairs.values()) {
            assertThat(pair).extracting(ActionProofCapturePlan.Plan::role).containsExactlyInAnyOrder("OWNER", "NONOWNER");
            assertThat(pair.stream().map(ActionProofCapturePlan.Plan::proofMode).distinct().count()).isEqualTo(1);
        }
        assertThat(plans.stream().filter(p -> p.role().equals("OWNER") && p.proofMode().equals("NOT_OBSERVED")).count()).isEqualTo(1);
        assertThat(plans.stream().filter(p -> p.role().equals("NONOWNER") && p.proofMode().equals("VERIFIED")).count()).isEqualTo(1);
    }
}
