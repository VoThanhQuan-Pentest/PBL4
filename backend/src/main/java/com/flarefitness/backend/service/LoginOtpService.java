package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.auth.LoginChallengeResponse;
import com.flarefitness.backend.dto.auth.LoginOtpRequest;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.dto.auth.LoginResponse;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.exception.TooManyRequestsException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.PasswordResetTokenStore;
import com.flarefitness.backend.security.TokenFingerprint;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Password proof creates no session. Only a current, single-use email proof can finish login. */
@Service
public class LoginOtpService {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginOtpService.class);
    private static final Duration TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DefaultRedisScript<Long> CONSUME = new DefaultRedisScript<>("""
            if redis.call('GET', KEYS[1]) ~= ARGV[1]
                or redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
            if tonumber(redis.call('GET', KEYS[2]) or '0') >= 5 then return 0 end
            if ARGV[3] == 'yes' then
                redis.call('DEL', KEYS[1], KEYS[3])
                return 1
            end
            local count = redis.call('INCR', KEYS[2])
            if count == 1 then redis.call('EXPIRE', KEYS[2], 300) end
            if count >= 5 then redis.call('DEL', KEYS[1], KEYS[3]) end
            return 0
            """, Long.class);
    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entities;
    private final AuthService auth;
    private final UserRepository users;
    private final StringRedisTemplate redis;
    private final PasswordEncoder encoder;
    private final JavaMailSender mail;
    private final String prefix;
    private final String from;
    private final boolean enabled;
    private final AuditLogService audit;

    public LoginOtpService(AuthService auth, UserRepository users, StringRedisTemplate redis,
            PasswordEncoder encoder, JavaMailSender mail,
            @Value("${app.otp.redis-prefix}") String prefix,
            @Value("${app.mail.from}") String from,
            @Value("${app.security.login-otp-enabled:false}") boolean enabled, AuditLogService audit) {
        this.auth = auth; this.users = users; this.redis = redis; this.encoder = encoder;
        this.mail = mail; this.prefix = prefix + "login:"; this.from = from; this.enabled = enabled;
        this.audit = audit;
    }

    public boolean isEnabled() { return enabled; }

    @Transactional
    public LoginChallengeResponse begin(LoginRequest request, String ip, String agent) {
        try {
            return beginChallenge(request, ip, agent);
        } catch (TooManyRequestsException rejected) {
            factorAudit(false, "AUTH_LOGIN_OTP_CHALLENGE_RATE_LIMITED", null, null);
            throw rejected;
        } catch (UnauthorizedException rejected) {
            factorAudit(false, "AUTH_LOGIN_OTP_CHALLENGE_REJECTED", null, null);
            throw rejected;
        } catch (RuntimeException failure) {
            factorAudit(false, "AUTH_LOGIN_OTP_CHALLENGE_ERROR", null, null);
            throw failure;
        }
    }

    private LoginChallengeResponse beginChallenge(LoginRequest request, String ip, String agent) {
        requireEnabled();
        User verified = auth.authenticateForLogin(request, ip, agent);
        requireContact(verified);
        String passwordProof = verified.getPassword();
        String identityProof = PasswordResetTokenStore.recoveryScope(verified);
        User user = users.findActiveByIdForUpdate(verified.getId()).orElseThrow(LoginOtpService::invalid);
        // A managed entity may already exist from the password lookup. Refresh after the lock.
        entities.refresh(user, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
        requireContact(user);
        // A password reset between credential validation and this lock must not create a new challenge.
        if (!Objects.equals(passwordProof, user.getPassword())
                || !identityProof.equals(PasswordResetTokenStore.recoveryScope(user))) {
            throw invalid();
        }
        requireActive(user);
        String account = accountKey(user.getId());
        if (attemptsExhausted(account)
                || !Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(account + ":cooldown", "1", Duration.ofSeconds(60)))) {
            throw new TooManyRequestsException("Vui long cho truoc khi yeu cau OTP dang nhap moi.");
        }
        String id = UUID.randomUUID().toString();
        String code = String.format(java.util.Locale.ROOT, "%06d", RANDOM.nextInt(1_000_000));
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(user.getId().getBytes(StandardCharsets.UTF_8))
                + "|" + PasswordResetTokenStore.recoveryScope(user) + "|" + clientBinding(ip, agent) + "|" + encoder.encode(code);
        redis.opsForValue().set(challengeKey(id), value, TTL);
        redis.opsForValue().set(account + ":active", id, TTL);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from); message.setTo(user.getEmail());
        message.setSubject("Flare - OTP dang nhap");
        message.setText("Ma OTP dang nhap: " + code + "\nHieu luc 5 phut. Khong chia se ma nay.");
        try {
            mail.send(message);
        } catch (RuntimeException failure) {
            redis.delete(challengeKey(id));
            // Keep the account cooldown even when SMTP fails; retries cannot flood the mailbox.
            throw new UnauthorizedException("Khong the gui OTP dang nhap. Vui long thu lai sau.");
        }
        String email = user.getEmail();
        // Password proof is not a completed login: keep the actor unassigned.
        factorAudit(true, "AUTH_LOGIN_EMAIL_OTP_ISSUED", null, user.getId());
        return new LoginChallengeResponse(id, TTL.toSeconds(), email.charAt(0) + "***" + email.substring(email.indexOf('@')), "EMAIL_OTP");
    }

    @Transactional
    public LoginResponse verify(LoginOtpRequest request, String ip, String agent) {
        try {
            return verifyProof(request, ip, agent);
        } catch (UnauthorizedException rejected) {
            // Missing proof can mean expired, consumed or unknown; do not guess.
            factorAudit(false, "AUTH_LOGIN_EMAIL_OTP_REJECTED", null, null);
            throw rejected;
        } catch (RuntimeException failure) {
            factorAudit(false, "AUTH_LOGIN_EMAIL_OTP_ERROR", null, null);
            throw failure;
        }
    }

    private LoginResponse verifyProof(LoginOtpRequest request, String ip, String agent) {
        requireEnabled();
        String value = redis.opsForValue().get(challengeKey(request.challengeId()));
        if (value == null) throw invalid();
        String[] fields = value.split("\\|", -1);
        if (fields.length != 4 || !clientBinding(ip, agent).equals(fields[2])) throw invalid();
        String userId;
        try { userId = new String(Base64.getUrlDecoder().decode(fields[0]), StandardCharsets.UTF_8); }
        catch (IllegalArgumentException malformed) { throw invalid(); }
        User user = users.findActiveByIdForUpdate(userId).orElseThrow(LoginOtpService::invalid);
        requireActive(user);
        requireContact(user);
        if (!PasswordResetTokenStore.recoveryScope(user).equals(fields[1])) throw invalid();
        String account = accountKey(userId);
        if (attemptsExhausted(account)) throw invalid();
        boolean matches = encoder.matches(request.otpCode(), fields[3]);
        Long result = redis.execute(CONSUME, List.of(challengeKey(request.challengeId()), account + ":attempts", account + ":active"),
                value, request.challengeId(), matches ? "yes" : "no");
        if (!Long.valueOf(1L).equals(result)) throw invalid();
        LoginResponse response = auth.completeLogin(user, ip, agent);
        factorAudit(true, "AUTH_LOGIN_EMAIL_OTP_VERIFIED", user.getId(), user.getId());
        return response;
    }

    private void factorAudit(boolean success, String action, String actor, String subject) {
        try {
            // Use the existing immediate-failure / after-commit-success contract.
            // Audit-only records do not enter the model's event-count features.
            if (success) audit.success(action, actor, subject, "AUTH_FACTOR", "EMAIL_OTP");
            else audit.failure(action, actor, subject, "AUTH_FACTOR", "EMAIL_OTP");
        } catch (RuntimeException failure) {
            LOGGER.warn("Login OTP audit delivery failed exceptionType={}", failure.getClass().getSimpleName());
        }
    }

    private boolean attemptsExhausted(String account) {
        String count = redis.opsForValue().get(account + ":attempts");
        return count != null && Integer.parseInt(count) >= 5;
    }
    private static void requireContact(User user) {
        if (user.getEmail() == null || user.getEmail().indexOf('@') < 1) throw invalid();
    }
    private void requireEnabled() { if (!enabled) throw invalid(); }
    private static void requireActive(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        if (!principal.isEnabled() || !principal.isAccountNonLocked()) throw invalid();
    }
    private String challengeKey(String id) { return prefix + "challenge:" + TokenFingerprint.sha256(id); }
    private String accountKey(String id) { return prefix + "account:" + TokenFingerprint.sha256(id); }
    private static String clientBinding(String ip, String agent) {
        String address = Objects.toString(ip, "");
        return TokenFingerprint.sha256(address.length() + ":" + address + Objects.toString(agent, ""));
    }
    private static UnauthorizedException invalid() {
        return new UnauthorizedException("OTP dang nhap khong hop le hoac da het han. Hay dang nhap lai.");
    }
}
