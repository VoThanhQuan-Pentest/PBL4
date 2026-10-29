package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.TooManyRequestsException;
import com.flarefitness.backend.service.EmailOtpService;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Real Redis proves salted storage, single-use CAS and replacement races; SMTP is captured in memory. */
@SpringBootTest(properties = "management.health.mail.enabled=false")
class AsvsOtpStorageIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired EmailOtpService otp;
    @Autowired StringRedisTemplate redis;
    @Autowired PasswordEncoder encoder;
    @Autowired Environment environment;
    @Autowired com.flarefitness.backend.service.AuthService auth;
    @Autowired com.flarefitness.backend.repository.CustomerRepository customers;
    @Autowired com.flarefitness.backend.repository.UserRepository users;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
    @MockitoBean JavaMailSender mail;
    private final ConcurrentHashMap<String, String> delivered = new ConcurrentHashMap<>();

    @BeforeEach void captureMail() {
        delivered.clear();
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var matcher = Pattern.compile("\\b[0-9]{6}\\b").matcher(message.getText());
            if (!matcher.find()) throw new AssertionError("Synthetic delivery contains no OTP");
            delivered.put(message.getTo()[0], matcher.group()); return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    @Test void registrationAuditDistinguishesDeliveryCompletionAndGenericRejections() {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("AUDIT");
        var previousLevel = logger.getLevel(); logger.setLevel(ch.qos.logback.classic.Level.INFO);
        var captured = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        captured.start(); logger.addAppender(captured);
        try {
            String username = "asvs-register-" + UUID.randomUUID(), email = email(), phone = availablePhone();
            auth.sendRegisterOtp(new com.flarefitness.backend.dto.auth.OtpRequest(username, email, phone), "192.0.2.186");
            String code = delivered.get(email); assertThat(code != null).isTrue();
            String wrong = "000000".equals(code) ? "000001" : "000000";
            assertThatThrownBy(() -> auth.register(registration(username, email, phone, wrong)))
                    .isInstanceOf(BadRequestException.class);
            var result = auth.register(registration(username, email, phone, code));
            assertThat(result.accessToken() != null && !result.accessToken().isBlank()).isTrue();
            assertThat(result.user().username()).isEqualTo(username);
            assertThatThrownBy(() -> auth.register(registration(username, email, phone, code)))
                    .isInstanceOf(BadRequestException.class);
            var events = captured.list.stream().filter(e -> e.getFormattedMessage().startsWith("action=AUTH_REGISTER_")).toList();
            assertThat(events).hasSize(4);
            assertThat(events.stream().filter(e -> e.getFormattedMessage().startsWith("action=AUTH_REGISTER_EMAIL_OTP_ISSUED outcome=SUCCESS actorId=- subjectId=- ")).count()).isEqualTo(1);
            assertThat(events.stream().filter(e -> e.getFormattedMessage().startsWith("action=AUTH_REGISTER_EMAIL_OTP_VERIFIED outcome=SUCCESS actorId=- ")).count()).isEqualTo(1);
            assertThat(events.stream().filter(e -> e.getFormattedMessage().startsWith("action=AUTH_REGISTER_ATTEMPT_REJECTED outcome=FAILURE actorId=- subjectId=- ")).count()).isEqualTo(2);
            assertThat(events.stream().allMatch(e -> {
                Object[] fields = e.getArgumentArray();
                return fields.length == 7 && "-".equals(fields[2])
                        && ("-".equals(fields[3]) || result.user().id().equals(fields[3]))
                        && "AUTH_FACTOR".equals(fields[4]) && "EMAIL_OTP".equals(fields[5]);
            })).isTrue();
            assertThat(captured.list.stream().filter(e -> e.getFormattedMessage().startsWith("action=ACCOUNT_REGISTER outcome=SUCCESS ")).count()).isEqualTo(1);
        } finally {
            logger.detachAppender(captured); captured.stop(); logger.setLevel(previousLevel);
        }
    }

    private String availablePhone() {
        for (int attempt = 0; attempt < 100; attempt++) {
            String phone = "09" + String.format(java.util.Locale.ROOT, "%08d",
                    Math.floorMod(UUID.randomUUID().hashCode(), 100_000_000));
            if (!customers.existsActiveBySdtIn(java.util.Set.of(phone, "+84" + phone.substring(1)))) return phone;
        }
        throw new AssertionError("Unable to allocate owned registration phone fixture");
    }

    @Test void registrationRollbackSuppressesSuccessAndEmitsOneGenericError() {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("AUDIT");
        var previousLevel = logger.getLevel(); logger.setLevel(ch.qos.logback.classic.Level.INFO);
        var captured = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        captured.start(); logger.addAppender(captured);
        com.flarefitness.backend.dto.auth.LoginResponse[] issued = new com.flarefitness.backend.dto.auth.LoginResponse[1];
        try {
            String username = "asvs-register-rollback-" + UUID.randomUUID(), email = email(), phone = availablePhone();
            auth.sendRegisterOtp(new com.flarefitness.backend.dto.auth.OtpRequest(username, email, phone), "192.0.2.187");
            String code = delivered.get(email); assertThat(code != null).isTrue();
            new org.springframework.transaction.support.TransactionTemplate(transactions).executeWithoutResult(status -> {
                issued[0] = auth.register(registration(username, email, phone, code));
                status.setRollbackOnly();
            });
            assertThat(users.existsByUsernameIgnoreCase(username)).isFalse();
            assertThat(captured.list.stream().filter(e -> e.getFormattedMessage()
                    .startsWith("action=AUTH_REGISTER_ATTEMPT_ERROR outcome=FAILURE actorId=- subjectId=- ")).count()).isEqualTo(1);
            assertThat(captured.list.stream().noneMatch(e -> e.getFormattedMessage().startsWith("action=AUTH_REGISTER_EMAIL_OTP_VERIFIED ")
                    || e.getFormattedMessage().startsWith("action=ACCOUNT_REGISTER "))).isTrue();
        } finally {
            // The existing Redis session side effect is outside the JPA transaction.
            try {
                if (issued[0] != null) auth.retirePreviousSession(issued[0].accessToken());
            } finally {
                logger.detachAppender(captured); captured.stop(); logger.setLevel(previousLevel);
            }
        }
    }

    private com.flarefitness.backend.dto.auth.RegisterRequest registration(String username, String email, String phone, String code) {
        return new com.flarefitness.backend.dto.auth.RegisterRequest(username, "Synthetic registration fixture", email, phone,
                "Asvs registration fixture password!", "Asvs registration fixture password!", code);
    }

    @Test void genericAndSensitiveCodesAreHashedAndConsumedOnlyOnce() {
        for (String purpose : new String[]{EmailOtpService.PURPOSE_REGISTER, EmailOtpService.PURPOSE_PROFILE_EMAIL}) {
            String email = email(); otp.sendOtp(purpose, email); String code = delivered.get(email);
            assertStoredHash(key(purpose, email), code);
            otp.verifyOtp(purpose, email, code);
            assertThat(redis.hasKey(key(purpose, email))).isFalse();
            assertThatThrownBy(() -> otp.verifyOtp(purpose, email, code)).isInstanceOf(BadRequestException.class);
        }
        String email = email(), scope = "a".repeat(64), account = "b".repeat(64);
        otp.sendSensitiveActionOtp(email, scope, account, "PASSWORD_CHANGE", null);
        String code = delivered.get(email); assertStoredHash(key("SENSITIVE_ACTION:" + scope, email), code);
        otp.verifySensitiveActionOtp(email, scope, account, code);
        assertThatThrownBy(() -> otp.verifySensitiveActionOtp(email, scope, account, code)).isInstanceOf(BadRequestException.class);
    }

    @Test void plaintextLeftByAnOlderBinaryCannotAuthorizeAnOperation() {
        String email = email(); redis.opsForValue().set(key("REGISTER", email), "123456", Duration.ofSeconds(300));
        assertThatThrownBy(() -> otp.verifyOtp("REGISTER", email, "123456")).isInstanceOf(BadRequestException.class);
    }

    @Test void concurrentVerificationCanConsumeAStoredHashOnlyOnce() throws Exception {
        String email = email(); otp.sendOtp("PROFILE_EMAIL", email); String code = delivered.get(email);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Boolean> attempt = () -> {
                try { otp.verifyOtp("PROFILE_EMAIL", email, code); return true; }
                catch (BadRequestException rejected) { return false; }
            };
            var result = executor.invokeAll(java.util.List.of(attempt, attempt));
            assertThat(java.util.List.of(result.get(0).get(), result.get(1).get())).containsExactlyInAnyOrder(true, false);
        }
    }

    @Test void aValidOldVerificationCannotConsumeAReplacementCode() throws Exception {
        String email = email(), key = key("PROFILE_EMAIL", email);
        CountDownLatch compared = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicBoolean pause = new AtomicBoolean(true);
        PasswordEncoder interleaved = new PasswordEncoder() {
            public String encode(CharSequence raw) { return encoder.encode(raw); }
            public boolean matches(CharSequence raw, String encoded) {
                boolean matched = encoder.matches(raw, encoded);
                if (pause.compareAndSet(true, false)) {
                    compared.countDown();
                    try { if (!resume.await(5, TimeUnit.SECONDS)) throw new AssertionError("Fixture interleave timed out"); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                }
                return matched;
            }
        };
        EmailOtpService service = new EmailOtpService(mail, redis, prefix(), 300, 60,
                "fixture", "fixture@example.test", "fixture", 5, interleaved);
        service.sendOtp("PROFILE_EMAIL", email); String oldCode = delivered.get(email);
        try (var executor = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            var pending = executor.submit(() -> {
                try { service.verifyOtp("PROFILE_EMAIL", email, oldCode); return true; }
                catch (BadRequestException rejected) { return false; }
            });
            try {
                assertThat(compared.await(5, TimeUnit.SECONDS)).isTrue();
                // Controlled producer replacement, without waiting a minute or relaxing send policy.
                redis.opsForValue().set(key, "h1:" + encoder.encode("654321"), Duration.ofSeconds(300));
            } finally { resume.countDown(); }
            assertThat(pending.get(5, TimeUnit.SECONDS)).isFalse();
            otp.verifyOtp("PROFILE_EMAIL", email, "654321");
        }
    }

    @Test void wrongCodesStillExhaustTheExistingFiveAttemptBudget() {
        String email = email(); otp.sendOtp("REGISTER", email); String code = delivered.get(email);
        String wrong = "000000".equals(code) ? "000001" : "000000";
        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> otp.verifyOtp("REGISTER", email, wrong)).isInstanceOf(BadRequestException.class);
        }
        assertThatThrownBy(() -> otp.verifyOtp("REGISTER", email, wrong)).isInstanceOf(TooManyRequestsException.class);
        assertThatThrownBy(() -> otp.verifyOtp("REGISTER", email, code)).isInstanceOf(TooManyRequestsException.class);
    }

    private void assertStoredHash(String key, String code) {
        String stored = redis.opsForValue().get(key);
        assertThat(stored != null && stored.startsWith("h1:{bcrypt-sha256}")).isTrue();
        assertThat(stored.equals(code)).isFalse();
        assertThat(encoder.matches(code, stored.substring(3))).isTrue();
        assertThat(redis.getExpire(key)).isBetween(1L, 300L);
    }
    private String prefix() { return environment.getRequiredProperty("app.otp.redis-prefix"); }
    private String key(String purpose, String email) { return prefix() + purpose + ":" + email; }
    private String email() { return "otp-storage-" + UUID.randomUUID() + "@example.test"; }
}
