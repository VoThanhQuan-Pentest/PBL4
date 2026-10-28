package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.security.TokenFingerprint;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

@SpringBootTest
class RedisSessionIndexIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired StringRedisTemplate redis;
    @Autowired Environment environment;
    private RedisTokenStore sessions;
    private String tokenPrefix;
    private String userPrefix;

    @BeforeEach void isolatedStore() {
        String prefix = environment.getRequiredProperty("flare.test.redis-namespace") + UUID.randomUUID() + ":";
        tokenPrefix = prefix + "token:";
        userPrefix = prefix + "user:";
        sessions = new RedisTokenStore(redis, tokenPrefix, userPrefix);
    }

    @Test void shorterSessionCannotShortenLongerSessionIndex() {
        sessions.save("long-session", "Alice", 600);
        sessions.save("short-session", "Alice", 5);
        assertLongIndex();
        sessions.revokeAll("ALICE");
        assertThat(sessions.contains("long-session")).isFalse();
        assertThat(sessions.contains("short-session")).isFalse();
    }

    @Test void migrationRetainsLongerSessionAndStillRemovesRawKeys() {
        sessions.save("long-session", "Alice", 600);
        redis.opsForValue().set(tokenPrefix + "legacy-session", "Alice", Duration.ofSeconds(10));
        redis.opsForSet().add(userPrefix + "alice", "legacy-session");
        assertThat(sessions.findUsername("legacy-session")).isEqualTo("Alice");
        assertThat(redis.hasKey(tokenPrefix + "legacy-session")).isFalse();
        assertLongIndex();
        // Remove only the migrated token, representing its earlier expiry.
        redis.delete(tokenPrefix + TokenFingerprint.sha256("legacy-session"));
        sessions.revokeAll("Alice");
        assertThat(sessions.contains("long-session")).isFalse();
    }

    @Test void absentIndexIsInitializedAndShorterIndexIsExtended() {
        sessions.save("short-session", "Alice", 5);
        assertThat(redis.getExpire(userPrefix + "alice", TimeUnit.MILLISECONDS)).isBetween(1L, 5000L);
        sessions.save("long-session", "Alice", 600);
        assertLongIndex();
        assertThat(redis.opsForSet().members(userPrefix + "alice")).containsExactlyInAnyOrder(
                TokenFingerprint.sha256("short-session"), TokenFingerprint.sha256("long-session"));
    }

    @Test void persistentLegacyIndexDoesNotAcquireAnUnsafeShortDeadline() {
        redis.opsForValue().set(tokenPrefix + "existing-legacy", "Alice", Duration.ofSeconds(600));
        redis.opsForSet().add(userPrefix + "alice", "existing-legacy");
        sessions.save("short-session", "Alice", 5);
        assertThat(redis.getExpire(userPrefix + "alice")).isEqualTo(-1L);
        sessions.revokeAll("Alice");
        assertThat(redis.hasKey(tokenPrefix + "existing-legacy")).isFalse();
        assertThat(sessions.contains("short-session")).isFalse();
    }

    @Test void concurrentSavesRetainTheLongestDeadline() throws Exception {
        try (var workers = Executors.newFixedThreadPool(2)) {
            var ready = new CountDownLatch(2);
            var start = new CountDownLatch(1);
            var longSave = workers.submit(() -> { ready.countDown(); await(start); sessions.save("long-session", "Alice", 600); });
            var shortSave = workers.submit(() -> { ready.countDown(); await(start); sessions.save("short-session", "Alice", 5); });
            try { assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue(); }
            finally { start.countDown(); }
            longSave.get(10, TimeUnit.SECONDS);
            shortSave.get(10, TimeUnit.SECONDS);
        }
        assertLongIndex();
        sessions.revokeAll("Alice");
        assertThat(sessions.contains("long-session")).isFalse();
        assertThat(sessions.contains("short-session")).isFalse();
    }

    @Test void idleAndAbsoluteDeadlinesRemainIndependent() {
        sessions = new RedisTokenStore(redis, tokenPrefix, userPrefix, 15);
        sessions.save("long-session", "Alice", 600);
        sessions.save("short-session", "Alice", 5);
        assertLongIndex();
        assertThat(redis.getExpire(tokenPrefix + "idle:" + TokenFingerprint.sha256("long-session"))).isBetween(1L, 15L);
        assertThat(redis.getExpire(tokenPrefix + TokenFingerprint.sha256("short-session"))).isBetween(1L, 5L);
        sessions.revokeAll("Alice");
        assertThat(sessions.contains("long-session")).isFalse();
        assertThat(sessions.contains("short-session")).isFalse();
    }

    private void assertLongIndex() {
        assertThat(redis.getExpire(userPrefix + "alice", TimeUnit.MILLISECONDS)).isBetween(590_000L, 600_000L);
    }

    private static void await(CountDownLatch latch) {
        try { if (!latch.await(10, TimeUnit.SECONDS)) throw new AssertionError("Save start deadline"); }
        catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
    }
}
