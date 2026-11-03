package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.CustomUserDetailsService;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.security.TokenFingerprint;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

@SpringBootTest
class RedisLegacySessionMigrationIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired StringRedisTemplate redis;
    @Autowired Environment environment;
    private final JwtTokenService jwt = new JwtTokenService("synthetic-migration-test-secret-at-least-thirty-two-characters", 600);
    private RedisTokenStore sessions;
    private CurrentUserPrincipal principal;
    private String tokenPrefix, userPrefix, token, rawKey, modernKey, indexKey;

    @BeforeEach void isolatedStore() {
        String prefix = environment.getRequiredProperty("flare.test.redis-namespace") + UUID.randomUUID() + ":";
        tokenPrefix = prefix + "token:"; userPrefix = prefix + "users:";
        sessions = new RedisTokenStore(redis, tokenPrefix, userPrefix);
        User user = new User(); user.setId("synthetic-migration-user"); user.setUsername("Alice");
        user.setRole("CUSTOMER"); user.setAuthVersion(0L); user.setDeleted(false); user.setStatus("Hoat dong");
        principal = new CurrentUserPrincipal(user); token = jwt.generateToken(principal);
        rawKey = tokenPrefix + token; modernKey = tokenPrefix + TokenFingerprint.sha256(token);
        indexKey = userPrefix + "alice";
    }

    @Test void bulkRevocationBeforeMigrationCannotReauthenticateToken() throws Exception {
        assertRevocationWins(true);
    }

    @Test void singleRevocationBeforeMigrationCannotReauthenticateToken() throws Exception {
        assertRevocationWins(false);
    }

    private void assertRevocationWins(boolean bulk) throws Exception {
        seed(Duration.ofSeconds(120));
        var delayed = delayedMigration(() -> {
            if (bulk) sessions.revokeAll("ALICE"); else sessions.revoke(token);
            assertThat(redis.hasKey(rawKey)).isFalse();
            assertThat(redis.hasKey(modernKey)).isFalse();
        });
        assertThat(authenticated(delayed)).isFalse();
        assertThat(authenticated(sessions)).isFalse();
        assertThat(redis.hasKey(rawKey)).isFalse();
        assertThat(redis.hasKey(modernKey)).isFalse();
    }

    @Test void migrationPreservesSubsecondDeadlineAndRemovesRawState() {
        seed(Duration.ofMillis(900));
        long before = redis.getExpire(rawKey, TimeUnit.MILLISECONDS);
        assertThat(sessions.findUsername(token)).isEqualTo("Alice");
        assertThat(redis.getExpire(modernKey, TimeUnit.MILLISECONDS)).isBetween(1L, before);
        assertThat(redis.hasKey(rawKey)).isFalse();
        assertThat(redis.opsForSet().members(indexKey)).containsExactly(TokenFingerprint.sha256(token));
        assertThat(redis.getExpire(indexKey)).isEqualTo(-1L);
    }

    @Test void persistentLegacyRecordIsRejectedAndCleaned() {
        redis.opsForValue().set(rawKey, "Alice"); redis.opsForSet().add(indexKey, token);
        assertThat(sessions.findUsername(token)).isNull();
        assertThat(redis.hasKey(rawKey)).isFalse();
        assertThat(redis.hasKey(modernKey)).isFalse();
        assertThat(redis.hasKey(indexKey)).isFalse();
    }

    @Test void disappearedLegacyRecordCannotBeCopied() {
        seed(Duration.ofSeconds(120));
        assertThat(delayedMigration(() -> redis.delete(rawKey)).findUsername(token)).isNull();
        assertThat(redis.hasKey(modernKey)).isFalse();
    }

    @Test void changedLegacyOwnerCannotBeCopiedIntoObservedAccount() {
        seed(Duration.ofSeconds(120));
        var delayed = delayedMigration(() -> redis.opsForValue().set(rawKey, "Mallory", Duration.ofSeconds(120)));
        assertThat(delayed.findUsername(token)).isNull();
        assertThat(redis.opsForValue().get(rawKey)).isEqualTo("Mallory");
        assertThat(redis.hasKey(modernKey)).isFalse();
    }

    @Test void concurrentModernRecordKeepsItsDeadline() {
        seed(Duration.ofSeconds(120));
        var delayed = delayedMigration(() -> {
            assertThat(sessions.findUsername(token)).isEqualTo("Alice");
            redis.expire(modernKey, Duration.ofSeconds(30));
        });
        assertThat(delayed.findUsername(token)).isEqualTo("Alice");
        assertThat(redis.getExpire(modernKey, TimeUnit.MILLISECONDS)).isBetween(1L, 30_000L);
    }

    @Test void concurrentModernRecordWithDifferentOwnerIsNotOverwritten() {
        seed(Duration.ofSeconds(120));
        var delayed = delayedMigration(() -> redis.opsForValue().set(modernKey, "Mallory", Duration.ofSeconds(30)));
        assertThat(delayed.findUsername(token)).isNull();
        assertThat(redis.opsForValue().get(modernKey)).isEqualTo("Mallory");
        assertThat(redis.getExpire(modernKey, TimeUnit.MILLISECONDS)).isBetween(1L, 30_000L);
    }

    @Test void absentOrShortIndexGetsTheRemainingLegacyHorizon() {
        seed(Duration.ofSeconds(120)); redis.delete(indexKey);
        assertThat(sessions.findUsername(token)).isEqualTo("Alice");
        assertThat(redis.getExpire(indexKey, TimeUnit.MILLISECONDS)).isBetween(118_000L, 120_000L);
        redis.delete(modernKey); seed(Duration.ofSeconds(120)); redis.expire(indexKey, Duration.ofSeconds(2));
        assertThat(sessions.findUsername(token)).isEqualTo("Alice");
        assertThat(redis.getExpire(indexKey, TimeUnit.MILLISECONDS)).isBetween(118_000L, 120_000L);
    }

    @Test void concurrentMigrationRequestsBothUseTheWinningRecord() throws Exception {
        seed(Duration.ofSeconds(120));
        var ready = new CountDownLatch(2);
        Runnable overlap = () -> {
            ready.countDown();
            try { if (!ready.await(10, TimeUnit.SECONDS)) throw new AssertionError("Migration overlap deadline"); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
        };
        var first = delayedMigration(overlap); var second = delayedMigration(overlap);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var a = workers.submit(() -> first.findUsername(token));
            var b = workers.submit(() -> second.findUsername(token));
            assertThat(a.get(10, TimeUnit.SECONDS)).isEqualTo("Alice");
            assertThat(b.get(10, TimeUnit.SECONDS)).isEqualTo("Alice");
        }
        assertThat(redis.hasKey(rawKey)).isFalse();
        assertThat(redis.opsForSet().members(indexKey)).containsExactly(TokenFingerprint.sha256(token));
    }

    @Test void enabledIdleEnforcementNeverMigratesLegacySessions() throws Exception {
        seed(Duration.ofSeconds(120));
        assertThat(authenticated(new RedisTokenStore(redis, tokenPrefix, userPrefix, 15))).isFalse();
        assertThat(redis.hasKey(modernKey)).isFalse();
    }

    private void seed(Duration ttl) {
        redis.opsForValue().set(rawKey, "Alice", ttl); redis.opsForSet().add(indexKey, token);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private RedisTokenStore delayedMigration(Runnable action) {
        var intercepted = spy(redis); var triggered = new AtomicBoolean();
        Runnable once = () -> { if (triggered.compareAndSet(false, true)) action.run(); };
        // The old implementation snapshots TTL outside Redis; the replacement
        // must instead observe revocation immediately before its atomic script.
        doAnswer(invocation -> { Long ttl = redis.getExpire(rawKey, TimeUnit.SECONDS); once.run(); return ttl; })
                .when(intercepted).getExpire(rawKey, TimeUnit.SECONDS);
        doAnswer(invocation -> {
            RedisScript<?> script = invocation.getArgument(0);
            if (script.getResultType() == String.class) once.run();
            return invocation.callRealMethod();
        }).when(intercepted).execute(any(RedisScript.class), anyList(), any(Object[].class));
        return new RedisTokenStore(intercepted, tokenPrefix, userPrefix);
    }

    private boolean authenticated(RedisTokenStore store) throws Exception {
        SecurityContextHolder.clearContext();
        try {
            var users = mock(CustomUserDetailsService.class);
            when(users.loadUserByUsername("Alice")).thenReturn(principal);
            var filter = new JwtAuthenticationFilter(jwt, store, users, "auth");
            var request = new MockHttpServletRequest("GET", "/api/products");
            request.addHeader("Authorization", "Bearer " + token);
            filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> { });
            return SecurityContextHolder.getContext().getAuthentication() != null;
        } finally { SecurityContextHolder.clearContext(); }
    }
}
