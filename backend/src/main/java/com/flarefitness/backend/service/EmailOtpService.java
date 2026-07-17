package com.flarefitness.backend.service;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.TooManyRequestsException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailOtpService {

    public static final String PURPOSE_REGISTER = "REGISTER";
    public static final String PURPOSE_FORGOT_PASSWORD = "FORGOT_PASSWORD";
    public static final String PURPOSE_PROFILE_EMAIL = "PROFILE_EMAIL";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final DefaultRedisScript<Long> VERIFY_OTP_ATOMICALLY = new DefaultRedisScript<>("""
            local code = redis.call('GET', KEYS[1])
            if not code then
              return 0
            end
            if code == ARGV[1] then
              redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
              return 1
            end
            local attempts = redis.call('INCR', KEYS[2])
            if attempts == 1 then
              local ttl = redis.call('TTL', KEYS[1])
              if ttl > 0 then
                redis.call('EXPIRE', KEYS[2], ttl)
              else
                redis.call('EXPIRE', KEYS[2], ARGV[3])
              end
            end
            if attempts >= tonumber(ARGV[2]) then
              redis.call('DEL', KEYS[1])
              return 3
            end
            return 2
            """, Long.class);

    private final JavaMailSender mailSender;
    private final StringRedisTemplate redisTemplate;
    private final String redisPrefix;
    private final long ttlSeconds;
    private final long cooldownSeconds;
    private final String mailUsername;
    private final String fromAddress;
    private final String mailPassword;
    private final int maxVerificationAttempts;

    public EmailOtpService(
            JavaMailSender mailSender,
            StringRedisTemplate redisTemplate,
            @Value("${app.otp.redis-prefix}") String redisPrefix,
            @Value("${app.otp.ttl-seconds}") long ttlSeconds,
            @Value("${app.otp.cooldown-seconds}") long cooldownSeconds,
            @Value("${spring.mail.username:}") String mailUsername,
            @Value("${app.mail.from}") String fromAddress,
            @Value("${spring.mail.password:}") String mailPassword,
            @Value("${app.otp.max-verification-attempts}") int maxVerificationAttempts
    ) {
        this.mailSender = mailSender;
        this.redisTemplate = redisTemplate;
        this.redisPrefix = redisPrefix;
        this.ttlSeconds = ttlSeconds;
        this.cooldownSeconds = cooldownSeconds;
        this.mailUsername = mailUsername;
        this.fromAddress = fromAddress;
        this.mailPassword = mailPassword;
        this.maxVerificationAttempts = maxVerificationAttempts;
    }

    public void sendOtp(String purpose, String email) {
        String normalizedPurpose = normalizePurpose(purpose);
        String normalizedEmail = normalizeEmail(email);
        assertMailConfigured();

        String cooldownKey = cooldownKey(normalizedPurpose, normalizedEmail);
        Boolean acquiredCooldown = redisTemplate.opsForValue().setIfAbsent(
                cooldownKey, "1", Duration.ofSeconds(cooldownSeconds));
        if (!Boolean.TRUE.equals(acquiredCooldown)) {
            throw new TooManyRequestsException("Vui long doi truoc khi gui lai ma OTP.");
        }

        String otpCode = generateOtpCode();
        redisTemplate.opsForValue().set(otpKey(normalizedPurpose, normalizedEmail), otpCode, Duration.ofSeconds(ttlSeconds));
        redisTemplate.delete(attemptKey(normalizedPurpose, normalizedEmail));

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(normalizedEmail);
        message.setSubject(buildSubject(normalizedPurpose));
        message.setText(buildBody(normalizedPurpose, otpCode));

        try {
            mailSender.send(message);
        } catch (MailException exception) {
            redisTemplate.delete(otpKey(normalizedPurpose, normalizedEmail));
            redisTemplate.delete(cooldownKey);
            redisTemplate.delete(attemptKey(normalizedPurpose, normalizedEmail));
            throw new BadRequestException("Khong the gui OTP qua email. Hay kiem tra cau hinh Gmail/App Password.");
        }
    }

    public void verifyOtp(String purpose, String email, String otpCode) {
        String normalizedPurpose = normalizePurpose(purpose);
        String normalizedEmail = normalizeEmail(email);
        String normalizedCode = String.valueOf(otpCode == null ? "" : otpCode).trim();

        if (!normalizedCode.matches("\\d{6}")) {
            throw new BadRequestException("Ma OTP khong hop le.");
        }

        String key = otpKey(normalizedPurpose, normalizedEmail);
        String attemptKey = attemptKey(normalizedPurpose, normalizedEmail);
        Long result = redisTemplate.execute(
                VERIFY_OTP_ATOMICALLY,
                List.of(key, attemptKey, cooldownKey(normalizedPurpose, normalizedEmail)),
                normalizedCode,
                Integer.toString(maxVerificationAttempts),
                Long.toString(Math.max(1L, ttlSeconds)));
        if (result != null && result == 1L) {
            return;
        }
        if (result != null && result == 3L) {
            throw new TooManyRequestsException("Ma OTP da bi khoa do nhap sai qua nhieu lan. Vui long yeu cau ma moi.");
        }
        throw new BadRequestException("Ma OTP khong dung hoac da het han.");
    }

    private void assertMailConfigured() {
        if (mailUsername == null || mailUsername.isBlank()
                || fromAddress == null || fromAddress.isBlank()
                || mailPassword == null || mailPassword.isBlank()) {
            throw new BadRequestException("Chua cau hinh day du APP_MAIL_USERNAME, APP_MAIL_FROM va APP_MAIL_PASSWORD.");
        }
    }

    private String buildSubject(String purpose) {
        if (PURPOSE_REGISTER.equals(purpose)) {
            return "Ma OTP dang ky tai khoan Flare Fitness";
        }
        if (PURPOSE_PROFILE_EMAIL.equals(purpose)) {
            return "Ma OTP xac nhan email moi Flare Fitness";
        }
        return "Ma OTP dat lai mat khau Flare Fitness";
    }

    private String buildBody(String purpose, String otpCode) {
        String action;
        if (PURPOSE_REGISTER.equals(purpose)) {
            action = "dang ky tai khoan";
        } else if (PURPOSE_PROFILE_EMAIL.equals(purpose)) {
            action = "xac nhan email moi";
        } else {
            action = "dat lai mat khau";
        }
        return """
                Xin chao,

                Ma OTP de %s tai Flare Fitness la: %s

                Ma co hieu luc trong %d phut. Vui long khong chia se ma nay voi bat ky ai.

                Flare Fitness
                """.formatted(action, otpCode, Math.max(1, ttlSeconds / 60));
    }

    private String generateOtpCode() {
        return String.format("%06d", SECURE_RANDOM.nextInt(1_000_000));
    }

    private String otpKey(String purpose, String email) {
        return redisPrefix + purpose + ":" + email;
    }

    private String cooldownKey(String purpose, String email) {
        return redisPrefix + "cooldown:" + purpose + ":" + email;
    }

    private String attemptKey(String purpose, String email) {
        return redisPrefix + "attempt:" + purpose + ":" + email;
    }

    private String normalizePurpose(String purpose) {
        String normalized = String.valueOf(purpose == null ? "" : purpose).trim().toUpperCase(Locale.ROOT);
        if (!PURPOSE_REGISTER.equals(normalized)
                && !PURPOSE_FORGOT_PASSWORD.equals(normalized)
                && !PURPOSE_PROFILE_EMAIL.equals(normalized)) {
            throw new BadRequestException("Loai OTP khong hop le.");
        }
        return normalized;
    }

    private String normalizeEmail(String email) {
        String normalized = String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new BadRequestException("Email la bat buoc.");
        }
        return normalized;
    }
}
