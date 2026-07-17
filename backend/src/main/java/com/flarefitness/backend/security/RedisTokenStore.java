package com.flarefitness.backend.security;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisTokenStore {

    private final StringRedisTemplate redisTemplate;
    private final String tokenPrefix;
    private final String userTokenPrefix;

    public RedisTokenStore(
            StringRedisTemplate redisTemplate,
            @Value("${app.security.token-prefix}") String tokenPrefix,
            @Value("${app.security.user-token-prefix}") String userTokenPrefix
    ) {
        this.redisTemplate = redisTemplate;
        this.tokenPrefix = tokenPrefix;
        this.userTokenPrefix = userTokenPrefix;
    }

    public void save(String token, String username, long ttlSeconds) {
        String fingerprint = fingerprint(token);
        redisTemplate.opsForValue().set(tokenKey(fingerprint), username, Duration.ofSeconds(ttlSeconds));
        String userKey = userKey(username);
        redisTemplate.opsForSet().add(userKey, fingerprint);
        redisTemplate.expire(userKey, Duration.ofSeconds(ttlSeconds));
    }

    public boolean contains(String token) {
        return findUsername(token) != null;
    }

    public String findUsername(String token) {
        String fingerprint = fingerprint(token);
        String username = redisTemplate.opsForValue().get(tokenKey(fingerprint));
        if (username != null) {
            return username;
        }

        // Compatibility for sessions created before key fingerprinting.  A
        // successful lookup is migrated immediately, so the raw token key is
        // removed on first use instead of remaining for its full JWT lifetime.
        String legacyKey = legacyTokenKey(token);
        username = redisTemplate.opsForValue().get(legacyKey);
        if (username == null) {
            return null;
        }
        Long ttlSeconds = redisTemplate.getExpire(legacyKey, TimeUnit.SECONDS);
        if (ttlSeconds == null || ttlSeconds <= 0) {
            redisTemplate.delete(legacyKey);
            redisTemplate.opsForSet().remove(userKey(username), token);
            return null;
        }
        save(token, username, ttlSeconds);
        redisTemplate.opsForSet().remove(userKey(username), token);
        redisTemplate.delete(legacyKey);
        return username;
    }

    public void revoke(String token) {
        String username = findUsername(token);
        String fingerprint = fingerprint(token);
        redisTemplate.delete(List.of(tokenKey(fingerprint), legacyTokenKey(token)));
        if (username != null) {
            redisTemplate.opsForSet().remove(userKey(username), fingerprint, token);
        }
    }

    public void revokeAll(String username) {
        if (username == null || username.isBlank()) {
            return;
        }
        String userKey = userKey(username);
        Set<String> tokens = redisTemplate.opsForSet().members(userKey);
        if (tokens != null && !tokens.isEmpty()) {
            // Current set members are SHA-256 fingerprints.  A legacy set can
            // still contain raw JWTs, however, so delete both representations
            // while revoking every device.  This is the only compatibility
            // path that constructs a raw key, and it removes it immediately.
            List<String> tokenKeys = tokens.stream()
                    .flatMap(member -> isFingerprint(member)
                            ? Stream.of(tokenKey(member))
                            : Stream.of(tokenKey(fingerprint(member)), legacyTokenKey(member)))
                    .distinct()
                    .toList();
            redisTemplate.delete(tokenKeys);
        }
        redisTemplate.delete(userKey);
    }

    private String fingerprint(String token) {
        return TokenFingerprint.sha256(token);
    }

    private String tokenKey(String fingerprint) {
        return tokenPrefix + fingerprint;
    }

    private String legacyTokenKey(String token) {
        return tokenPrefix + token;
    }

    private boolean isFingerprint(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private String userKey(String username) {
        return userTokenPrefix + String.valueOf(username == null ? "" : username).toLowerCase(Locale.ROOT);
    }
}
