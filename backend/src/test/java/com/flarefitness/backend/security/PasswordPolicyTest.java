package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.exception.BadRequestException;
import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    private final PasswordPolicy passwordPolicy = new PasswordPolicy();

    @Test
    void acceptsLongPassphrasesWithoutRequiringArtificialCompositionRules() {
        assertThatCode(() -> passwordPolicy.validateNewPassword("correct horse battery staple"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsPasswordsOutsideTheConfiguredLengthRange() {
        assertThatThrownBy(() -> passwordPolicy.validateNewPassword("short pass"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> passwordPolicy.validateNewPassword("x".repeat(129)))
                .isInstanceOf(BadRequestException.class);
    }
}
