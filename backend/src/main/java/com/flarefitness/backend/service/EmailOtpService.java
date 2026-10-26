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
    /** Separate namespace for the opt-in, test-only action-proof experiment. */
    public static final String PURPOSE_LAB_ACTION_PROOF = "LAB_ACTION_PROOF";
    public static final String PURPOSE_SENSITIVE_ACTION = "SENSITIVE_ACTION";

    /** Account-wide failure budget survives resend/new challenges; successful OTPs keep the cooldown. */
    private static final DefaultRedisScript<Long> VERIFY_SENSITIVE_ATOMICALLY = new DefaultRedisScript<>("""
            local failures = tonumber(redis.call('GET', KEYS[2]) or '0')
            if failures >= tonumber(ARGV[2]) then return 3 end
            local code = redis.call('GET', KEYS[1])
            if not code then return 0 end
            if code == ARGV[1] then
              redis.call('DEL', KEYS[1])
              return 1
            end
            local attempts = redis.call('INCR', KEYS[2])
            if attempts == 1 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
            if attempts >= tonumber(ARGV[2]) then
              redis.call('DEL', KEYS[1])
              return 3
            end
            return 2
            """, Long.class);

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
        sendOtp(purpose, email, null);
    }

    public void sendRecoveryOtp(com.flarefitness.backend.entity.User user) {
        sendOtp(PURPOSE_FORGOT_PASSWORD, user.getEmail(),
                com.flarefitness.backend.security.PasswordResetTokenStore.recoveryScope(user));
    }

    public void verifyRecoveryOtp(com.flarefitness.backend.entity.User user, String code) {
        verifyOtp(PURPOSE_FORGOT_PASSWORD, user.getEmail(), code,
                com.flarefitness.backend.security.PasswordResetTokenStore.recoveryScope(user));
    }

    public long sensitiveActionTtlSeconds() { return Math.max(1L, Math.min(300L, ttlSeconds)); }

    public void sendSensitiveActionOtp(String email, String scope, String accountScope,
            String operation, String targetEmail) {
        requireSensitiveScope(scope, accountScope);
        if (!"EMAIL_CHANGE".equals(operation) && !"PASSWORD_CHANGE".equals(operation)) {
            throw new BadRequestException("Thao tac xac nhan khong hop le.");
        }
        if (targetEmail != null && (targetEmail.length() > 150 || targetEmail.contains("\r") || targetEmail.contains("\n"))) {
            throw new BadRequestException("Dia chi dich khong hop le.");
        }
        String recipient = normalizeEmail(email);
        if (recipient.contains("\r") || recipient.contains("\n")) throw new BadRequestException("Email khong hop le.");
        String description = "EMAIL_CHANGE".equals(operation)
                ? "doi email tai khoan sang " + normalizeEmail(targetEmail) : "doi mat khau tai khoan";
        String namespace = PURPOSE_SENSITIVE_ACTION + ":" + accountScope;
        String failureKey = attemptKey(namespace, recipient);
        assertMailConfigured();
        String failures = redisTemplate.opsForValue().get(failureKey);
        int maximumAttempts = Math.max(1, Math.min(5, maxVerificationAttempts));
        if (failures != null && Long.parseLong(failures) >= maximumAttempts) {
            throw new TooManyRequestsException("Xac nhan dang tam khoa do nhap sai qua nhieu lan.");
        }
        String cooldown = cooldownKey(namespace, recipient);
        if (!Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(cooldown, "1",
                Duration.ofSeconds(Math.max(60L, cooldownSeconds))))) {
            throw new TooManyRequestsException("Vui long doi truoc khi gui lai ma xac nhan.");
        }
        String key = otpKey(PURPOSE_SENSITIVE_ACTION + ":" + scope, recipient);
        String code = generateOtpCode();
        redisTemplate.opsForValue().set(key, code, Duration.ofSeconds(sensitiveActionTtlSeconds()));
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(recipient);
        message.setSubject("Xac nhan thao tac tai khoan Flare Fitness");
        message.setText("Ban dang yeu cau " + description + ".\nMa xac nhan rieng cho thao tac nay: "
                + code + "\nMa het han sau " + sensitiveActionTtlSeconds()
                + " giay. Khong chia se ma. Neu khong yeu cau thao tac nay, khong xac nhan.");
        try {
            mailSender.send(message);
        } catch (MailException exception) {
            redisTemplate.delete(key);
            redisTemplate.delete(cooldown);
            // Never clear the account failure budget on delivery failure/resend.
            throw new BadRequestException("Khong gui duoc ma xac nhan. Thao tac chua duoc thuc hien.");
        }
    }

    public void verifySensitiveActionOtp(String email, String scope, String accountScope, String code) {
        requireSensitiveScope(scope, accountScope);
        if (code == null || !code.matches("\\d{6}")) throw new BadRequestException("Ma xac nhan phai gom 6 so.");
        String recipient = normalizeEmail(email);
        Long result = redisTemplate.execute(VERIFY_SENSITIVE_ATOMICALLY,
                List.of(otpKey(PURPOSE_SENSITIVE_ACTION + ":" + scope, recipient),
                        attemptKey(PURPOSE_SENSITIVE_ACTION + ":" + accountScope, recipient)),
                code, Integer.toString(Math.max(1, Math.min(5, maxVerificationAttempts))), "300");
        if (result != null && result == 1L) return;
        if (result != null && result == 3L) throw new TooManyRequestsException("Xac nhan dang tam khoa do nhap sai qua nhieu lan.");
        throw new com.flarefitness.backend.exception.ActionConfirmationCodeException();
    }

    private void requireSensitiveScope(String scope, String accountScope) {
        if (scope == null || !scope.matches("[0-9a-f]{64}")
                || accountScope == null || !accountScope.matches("[0-9a-f]{64}")) {
            throw new BadRequestException("Pham vi xac nhan khong hop le.");
        }
    }

    public void sendLabActionProofOtp(String email, String serverScopeSha256) {
        if (serverScopeSha256 == null) throw new BadRequestException("Pham vi OTP khong hop le.");
        sendOtp(PURPOSE_LAB_ACTION_PROOF, email, serverScopeSha256);
    }

    private void sendOtp(String purpose, String email, String scope) {
        String normalizedPurpose = normalizePurpose(purpose);
        String storagePurpose = scopedPurpose(normalizedPurpose, scope);
        String normalizedEmail = normalizeEmail(email);
        assertMailConfigured();

        String cooldownKey = cooldownKey(normalizedPurpose, normalizedEmail);
        Boolean acquiredCooldown = redisTemplate.opsForValue().setIfAbsent(
                cooldownKey, "1", Duration.ofSeconds(cooldownSeconds));
        if (!Boolean.TRUE.equals(acquiredCooldown)) {
            throw new TooManyRequestsException("Vui long doi truoc khi gui lai ma OTP.");
        }

        String otpCode = generateOtpCode();
        redisTemplate.opsForValue().set(otpKey(storagePurpose, normalizedEmail), otpCode, Duration.ofSeconds(ttlSeconds));
        redisTemplate.delete(attemptKey(storagePurpose, normalizedEmail));

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(normalizedEmail);
        message.setSubject(buildSubject(normalizedPurpose));
        message.setText(buildBody(normalizedPurpose, otpCode));

        try {
            mailSender.send(message);
        } catch (MailException exception) {
            redisTemplate.delete(otpKey(storagePurpose, normalizedEmail));
            redisTemplate.delete(cooldownKey);
            redisTemplate.delete(attemptKey(storagePurpose, normalizedEmail));
            throw new BadRequestException("Khong the gui OTP qua email. Hay kiem tra cau hinh Gmail/App Password.");
        }
    }

    public void verifyOtp(String purpose, String email, String otpCode) {
        verifyOtp(purpose, email, otpCode, null);
    }

    public void verifyLabActionProofOtp(String email, String serverScopeSha256, String otpCode) {
        if (serverScopeSha256 == null) throw new BadRequestException("Pham vi OTP khong hop le.");
        verifyOtp(PURPOSE_LAB_ACTION_PROOF, email, otpCode, serverScopeSha256);
    }

    private void verifyOtp(String purpose, String email, String otpCode, String scope) {
        String normalizedPurpose = normalizePurpose(purpose);
        String storagePurpose = scopedPurpose(normalizedPurpose, scope);
        String normalizedEmail = normalizeEmail(email);
        String normalizedCode = String.valueOf(otpCode == null ? "" : otpCode).trim();

        if (!normalizedCode.matches("\\d{6}")) {
            throw new BadRequestException("Ma OTP khong hop le.");
        }

        String key = otpKey(storagePurpose, normalizedEmail);
        String attemptKey = attemptKey(storagePurpose, normalizedEmail);
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
        if (PURPOSE_LAB_ACTION_PROOF.equals(purpose)) return "Ma xac nhan thao tac thu nghiem Flare Fitness";
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
        } else if (PURPOSE_LAB_ACTION_PROOF.equals(purpose)) {
            action = "xac nhan thao tac thu nghiem";
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
                && !PURPOSE_PROFILE_EMAIL.equals(normalized)
                && !PURPOSE_LAB_ACTION_PROOF.equals(normalized)) {
            throw new BadRequestException("Loai OTP khong hop le.");
        }
        return normalized;
    }

    private String scopedPurpose(String purpose, String scope) {
        if (scope == null) return purpose;
        if ((!PURPOSE_LAB_ACTION_PROOF.equals(purpose) && !PURPOSE_FORGOT_PASSWORD.equals(purpose))
                || !scope.matches("[0-9a-f]{64}")) {
            throw new BadRequestException("Pham vi OTP khong hop le.");
        }
        return purpose + ":" + scope;
    }

    private String normalizeEmail(String email) {
        String normalized = String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new BadRequestException("Email la bat buoc.");
        }
        return normalized;
    }
}
