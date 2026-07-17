package com.flarefitness.backend.security;

import com.flarefitness.backend.exception.TooManyRequestsException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

@Service
public class IpRateLimitService {

    private static final DefaultRedisScript<Long> INCREMENT_WITH_TTL = new DefaultRedisScript<>("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
              redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
            """, Long.class);

    /**
     * Reserves one login attempt in both buckets in one Redis operation.  The
     * reservation happens before BCrypt work, so concurrent requests cannot
     * all pass a read-then-increment gap and consume CPU unboundedly.
     */
    private static final DefaultRedisScript<Long> RESERVE_LOGIN_ATTEMPT = new DefaultRedisScript<>("""
            local ipCount = redis.call('INCR', KEYS[1])
            if ipCount == 1 then
              redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            local accountCount = redis.call('INCR', KEYS[2])
            if accountCount == 1 then
              redis.call('EXPIRE', KEYS[2], ARGV[1])
            end
            if ipCount > tonumber(ARGV[2]) or accountCount > tonumber(ARGV[3]) then
              return 0
            end
            return 1
            """, Long.class);

    private final StringRedisTemplate redisTemplate;
    private final String loginAttemptPrefix;
    private final int maxAttemptsPerMinute;
    private final int maxAccountAttemptsPerMinute;
    private final int maxOtpRequestsPerEmailPerHour;
    private final int maxOtpRequestsPerIpPerHour;
    private final int maxOtpRequestsPerEmailPerDay;
    private final int maxOtpRequestsPerIpPerDay;

    public IpRateLimitService(
            StringRedisTemplate redisTemplate,
            @Value("${app.security.login-attempt-prefix}") String loginAttemptPrefix,
            @Value("${app.security.login.max-attempts-per-minute}") int maxAttemptsPerMinute,
            @Value("${app.security.login.max-account-attempts-per-minute:${app.security.login.max-attempts-per-minute}}") int maxAccountAttemptsPerMinute,
            @Value("${app.security.otp.max-requests-per-email-per-hour:5}") int maxOtpRequestsPerEmailPerHour,
            @Value("${app.security.otp.max-requests-per-ip-per-hour:20}") int maxOtpRequestsPerIpPerHour,
            @Value("${app.security.otp.max-requests-per-email-per-day:20}") int maxOtpRequestsPerEmailPerDay,
            @Value("${app.security.otp.max-requests-per-ip-per-day:80}") int maxOtpRequestsPerIpPerDay
    ) {
        this.redisTemplate = redisTemplate;
        this.loginAttemptPrefix = loginAttemptPrefix;
        this.maxAttemptsPerMinute = maxAttemptsPerMinute;
        this.maxAccountAttemptsPerMinute = maxAccountAttemptsPerMinute;
        this.maxOtpRequestsPerEmailPerHour = maxOtpRequestsPerEmailPerHour;
        this.maxOtpRequestsPerIpPerHour = maxOtpRequestsPerIpPerHour;
        this.maxOtpRequestsPerEmailPerDay = maxOtpRequestsPerEmailPerDay;
        this.maxOtpRequestsPerIpPerDay = maxOtpRequestsPerIpPerDay;
    }

    /**
     * Atomically reserves an authentication attempt for both its source IP
     * and normalized username.  It must run before credential verification.
     */
    public void assertLoginAllowed(String ipAddress, String username) {
        Long allowed = redisTemplate.execute(
                RESERVE_LOGIN_ATTEMPT,
                List.of(loginIpKey(ipAddress), loginAccountKey(username)),
                Long.toString(Duration.ofMinutes(1).toSeconds()),
                Integer.toString(maxAttemptsPerMinute),
                Integer.toString(maxAccountAttemptsPerMinute));
        if (allowed == null || allowed != 1L) {
            throw new TooManyRequestsException("Dang nhap tam thoi bi gioi han. Vui long thu lai sau.");
        }
    }

    /**
     * A successful login only clears the account bucket.  It intentionally
     * leaves the shared IP bucket intact so success for one account cannot
     * erase failures against other accounts behind the same address.
     */
    public void recordSuccessfulLogin(String ipAddress, String username) {
        redisTemplate.delete(loginAccountKey(username));
    }

    public void assertOtpSendAllowed(String purpose, String email, String ipAddress) {
        String normalizedPurpose = String.valueOf(purpose == null ? "" : purpose).trim().toLowerCase(Locale.ROOT);
        String emailIdentifier = opaqueIdentifier(email);
        String ipIdentifier = opaqueIdentifier(ipAddress);
        assertAndIncrement("otp:" + normalizedPurpose + ":email:hour:" + emailIdentifier,
                maxOtpRequestsPerEmailPerHour, Duration.ofHours(1));
        assertAndIncrement("otp:" + normalizedPurpose + ":ip:hour:" + ipIdentifier,
                maxOtpRequestsPerIpPerHour, Duration.ofHours(1));
        assertAndIncrement("otp:email:day:" + emailIdentifier,
                maxOtpRequestsPerEmailPerDay, Duration.ofDays(1));
        assertAndIncrement("otp:ip:day:" + ipIdentifier,
                maxOtpRequestsPerIpPerDay, Duration.ofDays(1));
    }

    public void assertWithinLimit(String namespace, String identifier, int maxRequests, Duration window) {
        assertAndIncrement(namespace + ":" + opaqueIdentifier(identifier), maxRequests, window);
    }

    private void assertAndIncrement(String suffix, int maxRequests, Duration window) {
        Long count = incrementWithExpiry(loginAttemptPrefix + "limit:" + suffix, window);
        if (count != null && count > maxRequests) {
            throw new TooManyRequestsException("Ban da gui qua nhieu yeu cau. Vui long thu lai sau.");
        }
    }

    private Long incrementWithExpiry(String key, Duration window) {
        long seconds = Math.max(1L, window.toSeconds());
        return redisTemplate.execute(INCREMENT_WITH_TTL, List.of(key), Long.toString(seconds));
    }

    private String loginIpKey(String ipAddress) {
        return loginAttemptPrefix + "ip:" + opaqueIdentifier(ipAddress);
    }

    private String loginAccountKey(String username) {
        return loginAttemptPrefix + "account:" + opaqueIdentifier(
                String.valueOf(username == null ? "" : username).trim().toLowerCase(Locale.ROOT));
    }

    private String opaqueIdentifier(String value) {
        return TokenFingerprint.sha256(value);
    }
}
