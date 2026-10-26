package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

class PasswordResetTokenStoreTest {
    private PasswordResetTokenStore tokenStore;
    private ValueOperations<String, String> values;
    private final java.util.Map<String, String> storage = new ConcurrentHashMap<>();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        doAnswer(call -> { storage.put(call.getArgument(0), call.getArgument(1)); return null; })
                .when(values).set(any(String.class), any(String.class), any(Duration.class));
        when(values.getAndDelete(any(String.class))).thenAnswer(call -> storage.remove(call.getArgument(0)));
        tokenStore = new PasswordResetTokenStore(redis, "auth:password-reset:", 300);
    }

    private User user(String id) {
        User user = new User(); user.setId(id); user.setEmail("person@example.test"); user.setAuthVersion(0L);
        user.setEmailVerifiedAt(LocalDateTime.of(2026, 1, 1, 0, 0));
        return user;
    }

    @Test void issuedGrantStoresOnlyTokenAndIdentityFingerprintsWithTheConfiguredTtl() {
        String token = tokenStore.issue(user("account-a"));
        String key = "auth:password-reset:" + TokenFingerprint.sha256(token);
        assertThat(storage).containsKey(key);
        assertThat(key).doesNotContain(token);
        assertThat(storage.get(key)).matches("v2:[0-9a-f]{64}").doesNotContain("person@example.test");
        verify(values).set(eq(key), any(String.class), eq(Duration.ofSeconds(300)));
    }

    @Test void freshGrantWorksOnceForTheSameIdentityAndNormalizedContact() {
        User user = user("account-a"); String token = tokenStore.issue(user);
        user.setEmail(" PERSON@EXAMPLE.TEST ");
        tokenStore.consume(user, token);
        assertThatThrownBy(() -> tokenStore.consume(user, token)).isInstanceOf(BadRequestException.class);
    }

    @Test void oldGrantCannotResetADifferentAccountThatAcquiredTheSameEmail() {
        String token = tokenStore.issue(user("account-a"));
        assertThatThrownBy(() -> tokenStore.consume(user("account-b"), token)).isInstanceOf(BadRequestException.class);
    }

    @Test void changedAuthVersionInvalidatesTheGrant() {
        User user = user("account-a"); String token = tokenStore.issue(user); user.setAuthVersion(1L);
        assertThatThrownBy(() -> tokenStore.consume(user, token)).isInstanceOf(BadRequestException.class);
    }

    @Test void changedContactAndAwayThenBackContactVerificationInvalidateGrants() {
        for (boolean sameEmail : new boolean[]{false, true}) {
            User user = user("account-a"); String token = tokenStore.issue(user);
            if (!sameEmail) user.setEmail("other@example.test");
            else user.setEmailVerifiedAt(user.getEmailVerifiedAt().plusSeconds(1));
            assertThatThrownBy(() -> tokenStore.consume(user, token)).isInstanceOf(BadRequestException.class);
        }
    }

    @Test void unboundLegacyGrantsAndRawKeysAreNotAccepted() {
        for (boolean rawKey : new boolean[]{false, true}) {
            String token = java.util.UUID.randomUUID().toString();
            storage.put("auth:password-reset:" + (rawKey ? token : TokenFingerprint.sha256(token)), "person@example.test");
            assertThatThrownBy(() -> tokenStore.consume(user("account-a"), token)).isInstanceOf(BadRequestException.class);
            verify(values, never()).getAndDelete("auth:password-reset:" + token);
        }
    }
}
