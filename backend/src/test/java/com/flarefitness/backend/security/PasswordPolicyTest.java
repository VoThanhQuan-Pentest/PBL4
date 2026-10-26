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
    @Test
    void rejectsKnownCommonAndContextSpecificPasswordsWithoutTransformingAcceptedPassphrases() {
        assertThatThrownBy(() -> passwordPolicy.validateNewPassword("123456789012"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("danh sach");
        for (String password : java.util.List.of("FlareFitness2026!", "FL4RE-F1TNESS2026!", "PBL4 password 2026")) {
            assertThatThrownBy(() -> passwordPolicy.validateNewPassword(password))
                    .isInstanceOf(BadRequestException.class).hasMessageContaining("du an");
        }
        assertThatCode(() -> passwordPolicy.validateNewPassword("  amber rivers cross silent hills  "))
                .doesNotThrowAnyException();
    }

    @Test
    void unicodeLengthCountsCharactersRatherThanSurrogateHalves() {
        assertThatThrownBy(() -> passwordPolicy.validateNewPassword("🐚".repeat(6)))
                .isInstanceOf(BadRequestException.class);
        assertThatCode(() -> passwordPolicy.validateNewPassword("🐚".repeat(128))).doesNotThrowAnyException();
        assertThatThrownBy(() -> passwordPolicy.validateNewPassword("🐚".repeat(129)))
                .isInstanceOf(BadRequestException.class);
    }
}
