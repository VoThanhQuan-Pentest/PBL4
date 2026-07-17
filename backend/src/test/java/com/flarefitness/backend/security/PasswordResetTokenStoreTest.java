package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@ExtendWith(MockitoExtension.class)
class PasswordResetTokenStoreTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    private PasswordResetTokenStore tokenStore;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        tokenStore = new PasswordResetTokenStore(redisTemplate, "auth:password-reset:", 300);
    }

    @Test
    void issuedResetLinkIsStoredUnderAFingerprintNotTheRawSecret() {
        String token = tokenStore.issue("person@example.test");

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(keyCaptor.capture(), eq("person@example.test"), eq(Duration.ofSeconds(300)));
        assertThat(keyCaptor.getValue())
                .isEqualTo("auth:password-reset:" + TokenFingerprint.sha256(token))
                .doesNotContain(token);
    }
}
