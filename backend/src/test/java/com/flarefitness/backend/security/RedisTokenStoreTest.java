package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Collection;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@ExtendWith(MockitoExtension.class)
class RedisTokenStoreTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;
    @Mock private SetOperations<String, String> setOperations;

    private RedisTokenStore tokenStore;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        tokenStore = new RedisTokenStore(redisTemplate, "auth:token:", "auth:user-tokens:");
    }

    @Test
    void saveUsesFingerprintInsteadOfRawBearerTokenInRedisKeysAndSetMembers() {
        String rawToken = "eyJhbGciOiJIUzI1NiJ9.sensitive.payload";
        String fingerprint = TokenFingerprint.sha256(rawToken);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        tokenStore.save(rawToken, "Alice", 90);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(keyCaptor.capture(), eq("Alice"), eq(Duration.ofSeconds(90)));
        assertThat(keyCaptor.getValue()).isEqualTo("auth:token:" + fingerprint).doesNotContain(rawToken);
        verify(setOperations).add("auth:user-tokens:alice", fingerprint);
    }

    @Test
    void logoutAllAlsoRevokesLegacyRawTokenKeys() {
        String legacyRawToken = "legacy.jwt.sensitive-token";
        String currentFingerprint = TokenFingerprint.sha256("current.jwt.token");
        when(setOperations.members("auth:user-tokens:alice"))
                .thenReturn(Set.of(legacyRawToken, currentFingerprint));

        tokenStore.revokeAll("Alice");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<String>> keys = ArgumentCaptor.forClass(Collection.class);
        verify(redisTemplate).delete(keys.capture());
        assertThat(keys.getValue())
                .contains("auth:token:" + legacyRawToken)
                .contains("auth:token:" + TokenFingerprint.sha256(legacyRawToken))
                .contains("auth:token:" + currentFingerprint);
        verify(redisTemplate).delete("auth:user-tokens:alice");
    }
}
