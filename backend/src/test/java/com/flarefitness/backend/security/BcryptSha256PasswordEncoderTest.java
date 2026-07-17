package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BcryptSha256PasswordEncoderTest {

    private final BcryptSha256PasswordEncoder passwordEncoder = new BcryptSha256PasswordEncoder(4);

    @Test
    void longPasswordsDoNotSilentlyMatchWhenOnlyTheirTailDiffers() {
        String original = "x".repeat(128);
        String alteredTail = "x".repeat(72) + "y".repeat(56);
        String encoded = passwordEncoder.encode(original);

        assertThat(passwordEncoder.matches(original, encoded)).isTrue();
        assertThat(passwordEncoder.matches(alteredTail, encoded)).isFalse();
    }

    @Test
    void bareLegacyBcryptHashRemainsEligibleForUpgrade() {
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder legacy =
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4);
        String legacyHash = legacy.encode("legacy password");

        assertThat(passwordEncoder.matches("legacy password", legacyHash)).isTrue();
        assertThat(passwordEncoder.upgradeEncoding(legacyHash)).isTrue();
    }
}
