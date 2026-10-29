package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.TokenFingerprint;
import com.flarefitness.backend.service.AuthService;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Real API + MySQL/Redis, SMTP captured; no credentials or session cookies printed on failure. */
@SpringBootTest(properties = {"app.security.login-otp-enabled=true", "management.health.mail.enabled=false"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class AsvsLoginOtpIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired StringRedisTemplate redis;
    @Autowired Environment environment;
    @Autowired AuthService auth;
    @Autowired com.flarefitness.backend.security.JwtTokenService jwt;
    @Autowired com.flarefitness.backend.security.RedisTokenStore sessions;
    @Autowired com.flarefitness.backend.service.siem.SiemSessionRevocationEvidence revocations;
    @MockitoBean JavaMailSender mail;
    private final Map<String, String> codes = new ConcurrentHashMap<>();
    private static final String PASSWORD = "Synthetic!LoginPassphrase1";
    private static final String IP = "192.0.2.141";
    private static final String AGENT = "ASVS synthetic OTP client";

    @BeforeEach void captureMail() {
        codes.clear();
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var matcher = Pattern.compile("\\b[0-9]{6}\\b").matcher(message.getText());
            if (!matcher.find()) throw new AssertionError("Synthetic OTP delivery missing code");
            codes.put(message.getTo()[0], matcher.group());
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    @Test void passwordProofCreatesNoSessionAndOtpIsSingleUse() throws Exception {
        User user = fixture(); Challenge challenge = begin(user);
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
        MvcResult result = verify(challenge, codes.get(user.getEmail()), IP, AGENT);
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(result.getResponse().getCookie("access_token") != null).isTrue();
        assertThat(mapper.readTree(result.getResponse().getContentAsString()).hasNonNull("access_token")).isFalse();
        var current = mvc.perform(get("/api/auth/me").cookie(result.getResponse().getCookie("access_token")))
                .andExpect(status().isOk()).andReturn();
        assertThat(mapper.readTree(current.getResponse().getContentAsString()).path("id").asText()).isEqualTo(user.getId());
        assertThat(verify(challenge, codes.get(user.getEmail()), IP, AGENT).getResponse().getStatus()).isEqualTo(401);
    }

    @Test void emailFactorAuditDistinguishesIssuanceRejectionAndCompletedVerification() throws Exception {
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("AUDIT");
        var previousLevel = logger.getLevel();
        logger.setLevel(ch.qos.logback.classic.Level.INFO);
        var captured = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        captured.start();
        logger.addAppender(captured);
        try {
            User user = fixture();
            Challenge challenge = begin(user);
            String code = codes.get(user.getEmail());
            String wrong = "000000".equals(code) ? "000001" : "000000";
            assertThat(verify(challenge, wrong, IP, AGENT).getResponse().getStatus()).isEqualTo(401);
            assertThat(verify(challenge, code, IP, AGENT).getResponse().getStatus()).isEqualTo(200);
            assertThat(verify(challenge, code, IP, AGENT).getResponse().getStatus()).isEqualTo(401);
            var messages = captured.list.stream().map(event -> event.getFormattedMessage()).toList();
            assertThat(messages.stream().filter(m -> m.startsWith("action=AUTH_LOGIN_EMAIL_OTP_ISSUED outcome=SUCCESS actorId=- ")).count()).isEqualTo(1);
            assertThat(messages.stream().filter(m -> m.startsWith("action=AUTH_LOGIN_EMAIL_OTP_VERIFIED outcome=SUCCESS ")).count()).isEqualTo(1);
            assertThat(messages.stream().filter(m -> m.startsWith("action=AUTH_LOGIN_EMAIL_OTP_REJECTED outcome=FAILURE actorId=- subjectId=- ")).count()).isEqualTo(2);
            assertThat(messages.stream().filter(m -> m.startsWith("action=AUTH_LOGIN outcome=SUCCESS ")).count()).isEqualTo(1);
            // Check the permitted data slots, not arbitrary substrings of random IDs.
            // Boolean assertions also keep synthetic secrets out of failure output.
            assertThat(captured.list.stream().filter(e -> e.getFormattedMessage().startsWith("action=AUTH_LOGIN_EMAIL_OTP_"))
                    .allMatch(e -> {
                        Object[] fields = e.getArgumentArray();
                        return fields.length == 7
                                && ("-".equals(fields[2]) || user.getId().equals(fields[2]))
                                && ("-".equals(fields[3]) || user.getId().equals(fields[3]))
                                && "AUTH_FACTOR".equals(fields[4]) && "EMAIL_OTP".equals(fields[5]);
                    })).isTrue();
        } finally {
            logger.detachAppender(captured);
            captured.stop();
            logger.setLevel(previousLevel);
        }
    }

    @Test void onlySuccessfulOtpRetiresThePresentedSessionAndLeavesOtherDevicesIntact() throws Exception {
        User user = fixture();
        var previous = existingSession(user);
        var otherDevice = existingSession(user);
        Challenge challenge = begin(user, previous);
        mvc.perform(get("/api/auth/me").cookie(previous)).andExpect(status().isOk());
        String code = codes.get(user.getEmail());
        String wrong = code.equals("000000") ? "000001" : "000000";
        assertThat(verify(challenge, wrong, IP, AGENT, previous).getResponse().getStatus()).isEqualTo(401);
        mvc.perform(get("/api/auth/me").cookie(previous)).andExpect(status().isOk());
        MvcResult completed = verify(challenge, code, IP, AGENT, previous);
        assertThat(completed.getResponse().getStatus()).isEqualTo(200);
        var replacement = completed.getResponse().getCookie("access_token");
        assertThat(replacement).isNotNull();
        assertThat(replacement.getValue().equals(previous.getValue())).isFalse();
        mvc.perform(get("/api/auth/me").cookie(previous)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/me").cookie(replacement)).andExpect(status().isOk());
        mvc.perform(get("/api/auth/me").cookie(otherDevice)).andExpect(status().isOk());
        assertThat(revocations.find(previous.getValue(), user.getId())).isNull();
    }

    @Test void concurrentVerificationCanIssueOnlyOneSession() throws Exception {
        User user = fixture(); Challenge challenge = begin(user); String code = codes.get(user.getEmail());
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Integer> attempt = () -> verify(challenge, code, IP, AGENT).getResponse().getStatus();
            var results = executor.invokeAll(java.util.List.of(attempt, attempt));
            assertThat(java.util.List.of(results.get(0).get(), results.get(1).get())).containsExactlyInAnyOrder(200, 401);
        }
    }

    @Test void challengeCannotMoveToAnotherClient() throws Exception {
        User user = fixture(); Challenge challenge = begin(user); String code = codes.get(user.getEmail());
        assertThat(verify(challenge, code, "192.0.2.142", AGENT).getResponse().getStatus()).isEqualTo(401);
        assertThat(verify(challenge, code, IP, "Another client").getResponse().getStatus()).isEqualTo(401);
        assertThat(verify(challenge, code, IP, AGENT).getResponse().getStatus()).isEqualTo(200);
    }

    @Test void aNewSecurityEpochInvalidatesPendingProof() throws Exception {
        User user = fixture(); Challenge challenge = begin(user);
        user.setAuthVersion(user.getAuthVersion() + 1); users.saveAndFlush(user);
        assertThat(verify(challenge, codes.get(user.getEmail()), IP, AGENT).getResponse().getStatus()).isEqualTo(401);
    }

    @Test void accountIsolationAfterPasswordProofPreventsLogin() throws Exception {
        User user = fixture(); Challenge challenge = begin(user);
        user.setSocIsolated(true); users.saveAndFlush(user);
        assertThat(verify(challenge, codes.get(user.getEmail()), IP, AGENT).getResponse().getStatus()).isEqualTo(401);
    }

    @Test void fiveFailuresExhaustTheAccountBudgetAndRestartCannotResetIt() throws Exception {
        User user = fixture(); Challenge challenge = begin(user); String code = codes.get(user.getEmail());
        String wrong = code.equals("000000") ? "000001" : "000000";
        for (int attempt = 0; attempt < 5; attempt++) {
            assertThat(verify(challenge, wrong, IP, AGENT).getResponse().getStatus()).isEqualTo(401);
        }
        assertThat(verify(challenge, code, IP, AGENT).getResponse().getStatus()).isEqualTo(401);
        assertThat(login(user, PASSWORD).getResponse().getStatus()).isEqualTo(429);
    }

    @Test void expiredProofAndLegacyServiceEntryCannotIssueSessions() throws Exception {
        User user = fixture(); Challenge challenge = begin(user);
        String key = environment.getRequiredProperty("app.otp.redis-prefix") + "login:challenge:"
                + TokenFingerprint.sha256(challenge.id());
        redis.delete(key); // Controlled expiration, without waiting five minutes.
        assertThat(verify(challenge, codes.get(user.getEmail()), IP, AGENT).getResponse().getStatus()).isEqualTo(401);
        assertThatThrownBy(() -> auth.login(new LoginRequest(user.getUsername(), PASSWORD), IP, AGENT))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test void anAccountWithoutARecoveryContactFailsClosedWithoutSendingMail() throws Exception {
        User user = fixture(); user.setEmail(null); users.saveAndFlush(user);
        MvcResult result = login(user, PASSWORD);
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
        assertThat(codes).isEmpty();
    }

    @Test void wrongPasswordCannotSendMailOrCreateAChallenge() throws Exception {
        User user = fixture(); MvcResult result = login(user, "Wrong!Passphrase");
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
        assertThat(codes.containsKey(user.getEmail())).isFalse();
    }

    @Test void otpSubmissionStillRequiresCsrf() throws Exception {
        User user = fixture(); Challenge challenge = begin(user);
        mvc.perform(post("/api/auth/login/otp").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("challenge_id", challenge.id(), "otp_code", codes.get(user.getEmail())))))
                .andExpect(status().isForbidden());
    }

    private Challenge begin(User user, jakarta.servlet.http.Cookie... existing) throws Exception {
        MvcResult result = login(user, PASSWORD, existing);
        assertThat(result.getResponse().getStatus()).isEqualTo(202);
        // Existing authenticated clients may receive CSRF-cookie rotation here;
        // the password-only step must never issue an authentication cookie.
        assertThat(result.getResponse().getCookie("access_token")).isNull();
        assertThat(result.getResponse().getHeaders("Set-Cookie"))
                .noneMatch(header -> header.startsWith("access_token="));
        var body = mapper.readTree(result.getResponse().getContentAsString());
        assertThat(body.has("access_token")).isFalse();
        assertThat(body.path("expires_in").asLong()).isEqualTo(300);
        assertThat(body.path("email_masked").asText()).doesNotContain(user.getUsername());
        return new Challenge(body.path("challenge_id").asText());
    }
    private MvcResult login(User user, String password, jakarta.servlet.http.Cookie... existing) throws Exception {
        String csrf = csrf();
        var builder = post("/api/auth/login").with(request -> { request.setRemoteAddr(IP); return request; })
                .header("User-Agent", AGENT).cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("username", user.getUsername(), "password", password)));
        if (existing.length > 0) builder.cookie(existing);
        return mvc.perform(builder).andReturn();
    }
    private MvcResult verify(Challenge challenge, String code, String ip, String agent, jakarta.servlet.http.Cookie... existing) throws Exception {
        String csrf = csrf();
        var builder = post("/api/auth/login/otp").with(request -> { request.setRemoteAddr(ip); return request; })
                .header("User-Agent", agent).cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("challenge_id", challenge.id(), "otp_code", code)));
        if (existing.length > 0) builder.cookie(existing);
        return mvc.perform(builder).andReturn();
    }

    private MockCookie existingSession(User user) {
        String token = jwt.generateToken(new com.flarefitness.backend.security.CurrentUserPrincipal(user));
        sessions.save(token, user.getUsername(), 3600);
        return new MockCookie("access_token", token);
    }
    private String csrf() throws Exception {
        return mapper.readTree(mvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getContentAsString()).path("token").asText();
    }
    private User fixture() {
        String id = "asvs-login-" + UUID.randomUUID();
        User user = new User(); user.setId(id); user.setUsername(id); user.setRole("SOC L1");
        user.setPassword(passwords.encode(PASSWORD)); user.setEmail(id + "@example.test");
        user.setEmailVerifiedAt(LocalDateTime.now().withNano(0)); user.setHoTen("Synthetic login fixture");
        user.setStatus("Hoat dong"); user.setCreatedAt(LocalDateTime.now()); user.setDeleted(false);
        return users.saveAndFlush(user);
    }
    private record Challenge(String id) { }
}
