package com.flarefitness.backend.security;

import com.flarefitness.backend.exception.BadRequestException;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class PasswordResetTokenStore {

    private final StringRedisTemplate redisTemplate;
    private final String tokenPrefix;
    private final long ttlSeconds;

    public PasswordResetTokenStore(
            StringRedisTemplate redisTemplate,
            @Value("${app.security.password-reset-token-prefix}") String tokenPrefix,
            @Value("${app.security.password-reset-token-ttl-seconds}") long ttlSeconds
    ) {
        this.redisTemplate = redisTemplate;
        this.tokenPrefix = tokenPrefix;
        this.ttlSeconds = ttlSeconds;
    }

    public String issue(String email) {
        String token = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(key(token), normalizeEmail(email), Duration.ofSeconds(ttlSeconds));
        return token;
    }

    public void consume(String email, String token) {
        String normalizedToken = String.valueOf(token == null ? "" : token).trim();
        String storedEmail = redisTemplate.opsForValue().getAndDelete(key(normalizedToken));
        if (storedEmail == null) {
            // Compatibility for short-lived reset links created before token
            // fingerprinting was introduced. The legacy key is deleted on use.
            storedEmail = redisTemplate.opsForValue().getAndDelete(legacyKey(normalizedToken));
        }
        if (storedEmail == null || !storedEmail.equals(normalizeEmail(email))) {
            throw new BadRequestException("Phien dat lai mat khau khong hop le hoac da het han.");
        }
    }

    private String key(String token) {
        return tokenPrefix + TokenFingerprint.sha256(token);
    }

    private String legacyKey(String token) {
        return tokenPrefix + token;
    }

    private String normalizeEmail(String email) {
        return String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
    }
}
