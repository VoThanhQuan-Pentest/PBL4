package com.flarefitness.backend.security;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.entity.User;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class PasswordResetTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();

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

    public String issue(User user) {
        byte[] entropy = new byte[32];
        RANDOM.nextBytes(entropy);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(entropy);
        redisTemplate.opsForValue().set(key(token), binding(user), Duration.ofSeconds(ttlSeconds));
        return token;
    }

    public void consume(User user, String token) {
        String normalizedToken = String.valueOf(token == null ? "" : token).trim();
        String storedBinding = redisTemplate.opsForValue().getAndDelete(key(normalizedToken));
        // Email-only and raw-key legacy grants cannot establish account identity.
        // They expire normally; the user must complete a fresh recovery challenge.
        if (!binding(user).equals(storedBinding)) {
            throw new BadRequestException("Phien dat lai mat khau khong hop le hoac da het han.");
        }
    }

    private String binding(User user) {
        return "v2:" + recoveryScope(user);
    }

    /** Server-authored identity shared by the OTP and its single-use reset grant. */
    public static String recoveryScope(User user) {
        String id = user.getId();
        String email = normalizeEmail(user.getEmail());
        long version = user.getAuthVersion() == null ? 0L : user.getAuthVersion();
        if (id == null || id.isBlank() || email.isBlank() || version < 0) {
            throw new IllegalArgumentException("Recovery requires a persisted account identity");
        }
        StringBuilder identity = new StringBuilder();
        for (String field : java.util.List.of(id, Long.toString(version), email,
                user.getEmailVerifiedAt() == null ? "-" : user.getEmailVerifiedAt().toString())) {
            identity.append(field.length()).append(':').append(field);
        }
        return TokenFingerprint.sha256(identity.toString());
    }

    private String key(String token) {
        return tokenPrefix + TokenFingerprint.sha256(token);
    }

    private static String normalizeEmail(String email) {
        return String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
    }
}
