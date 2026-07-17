package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;

class SecurityConfigTest {

    @Test
    void passwordEncoderUsesBcryptCostTwelve() {
        PasswordEncoder passwordEncoder = new SecurityConfig(null, null, null).passwordEncoder();

        assertThat(passwordEncoder.encode("correct horse battery staple"))
                .startsWith(BcryptSha256PasswordEncoder.PREFIX + "$2a$12$");
    }
}
