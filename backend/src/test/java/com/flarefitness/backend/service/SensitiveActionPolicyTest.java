package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.User;
import org.junit.jupiter.api.Test;

class SensitiveActionPolicyTest {
    @Test void defaultDisabledPolicyDoesNotChangeAccounts() {
        User user = new User(); user.setId("lab-a");
        assertThat(new SensitiveActionPolicy(false, "").requiresConfirmation(user)).isFalse();
    }

    @Test void activationRequiresExplicitAccountAllowlistAndCannotUseWildcard() {
        assertThatThrownBy(() -> new SensitiveActionPolicy(true, "")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SensitiveActionPolicy(true, "*")).isInstanceOf(IllegalArgumentException.class);
        User first = new User(); first.setId("lab-a");
        User other = new User(); other.setId("other");
        var policy = new SensitiveActionPolicy(true, "lab-a, lab-b");
        assertThat(policy.requiresConfirmation(first)).isTrue();
        assertThat(policy.requiresConfirmation(other)).isFalse();
    }
}
