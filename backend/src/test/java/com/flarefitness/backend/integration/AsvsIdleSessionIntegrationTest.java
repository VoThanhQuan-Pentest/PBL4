package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.security.TokenFingerprint;
import com.flarefitness.backend.service.AuthService;
import java.time.Duration;
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
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {"app.security.session-idle-seconds=900", "app.jwt.expiration-seconds=28800",
        "app.security.login-otp-enabled=true", "management.health.mail.enabled=false"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class AsvsIdleSessionIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired StringRedisTemplate redis;
    @Autowired RedisTokenStore sessions;
    @Autowired AuthService auth;
    @Autowired Environment environment;
    @MockitoBean JavaMailSender mail;
    private final ConcurrentHashMap<String, String> codes = new ConcurrentHashMap<>();
    private static final String IP = "192.0.2.181", AGENT = "ASVS idle fixture", PASSWORD = "Synthetic!IdleSession1";

    @BeforeEach void captureMail() {
        codes.clear();
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var matcher = Pattern.compile("\\b[0-9]{6}\\b").matcher(message.getText());
            if (!matcher.find()) throw new AssertionError("Synthetic delivery missing OTP");
            codes.put(message.getTo()[0], matcher.group()); return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    @Test void passiveAuthenticatedPollingDoesNotExtendTheIdleDeadline() throws Exception {
        Session session = login(); redis.expire(session.idle(), Duration.ofSeconds(30));
        for (int i = 0; i < 3; i++) me(session, false, 200);
        assertThat(redis.getExpire(session.idle())).isBetween(1L, 30L);
    }

    @Test void interactionRenewsOnlyTheIdleDeadline() throws Exception {
        Session session = login(); redis.expire(session.idle(), Duration.ofSeconds(30));
        long absoluteBefore = redis.getExpire(session.absolute(), java.util.concurrent.TimeUnit.MILLISECONDS);
        me(session, true, 200);
        assertThat(redis.getExpire(session.idle())).isBetween(850L, 900L);
        assertThat(redis.getExpire(session.absolute(), java.util.concurrent.TimeUnit.MILLISECONDS)).isLessThanOrEqualTo(absoluteBefore);
    }

    @Test void renewalCannotOutliveTheAbsoluteDeadline() throws Exception {
        Session session = login(); redis.expire(session.absolute(), Duration.ofSeconds(300));
        redis.expire(session.idle(), Duration.ofSeconds(30));
        me(session, true, 200);
        assertThat(redis.getExpire(session.idle())).isBetween(31L, 300L);
        assertThat(redis.getExpire(session.absolute())).isBetween(1L, 300L);
    }

    @Test void interactionCannotReviveAnExpiredIdleSession() throws Exception {
        Session session = login(); redis.delete(session.idle());
        me(session, true, 401); sessions.renewIdle(session.cookie().getValue());
        assertThat(redis.hasKey(session.absolute())).isFalse();
        assertThat(redis.hasKey(session.idle())).isFalse();
    }

    @Test void logoutAllDeletesBothSessionRecordsAndTheyStayRevoked() throws Exception {
        Session session = login(); auth.logoutAll(session.username());
        me(session, true, 401); sessions.renewIdle(session.cookie().getValue());
        assertThat(redis.hasKey(session.absolute())).isFalse();
        assertThat(redis.hasKey(session.idle())).isFalse();
    }

    @Test void aLegacyRawTokenKeyCannotBypassTheNewIdleRequirement() throws Exception {
        Session session = login(); redis.delete(java.util.List.of(session.absolute(), session.idle()));
        redis.opsForValue().set(prefix() + session.cookie().getValue(), session.username(), Duration.ofSeconds(300));
        me(session, true, 401);
        assertThat(redis.hasKey(session.absolute())).isFalse();
        assertThat(redis.hasKey(session.idle())).isFalse();
    }

    private Session login() throws Exception {
        String id = "asvs-idle-" + UUID.randomUUID();
        User user = new User(); user.setId(id); user.setUsername(id); user.setEmail(id + "@example.test");
        user.setPassword(encoder.encode(PASSWORD)); user.setRole("Khach hang"); user.setHoTen("Synthetic idle fixture");
        user.setStatus("Hoat dong"); user.setDeleted(false); user.setCreatedAt(LocalDateTime.now()); users.saveAndFlush(user);
        String csrf = csrf();
        var beginning = mvc.perform(post("/api/auth/login").with(request -> { request.setRemoteAddr(IP); return request; })
                .header("User-Agent", AGENT).cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("username", id, "password", PASSWORD))))
                .andExpect(status().isAccepted()).andReturn();
        String challenge = mapper.readTree(beginning.getResponse().getContentAsString()).path("challenge_id").asText();
        csrf = csrf();
        var completed = mvc.perform(post("/api/auth/login/otp").with(request -> { request.setRemoteAddr(IP); return request; })
                .header("User-Agent", AGENT).cookie(new MockCookie("XSRF-TOKEN", csrf)).header("X-XSRF-TOKEN", csrf)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("challenge_id", challenge, "otp_code", codes.get(user.getEmail())))))
                .andExpect(status().isOk()).andReturn();
        MockCookie cookie = MockCookie.parse(completed.getResponse().getHeader("Set-Cookie"));
        String fingerprint = TokenFingerprint.sha256(cookie.getValue());
        assertThat(redis.getExpire(prefix() + fingerprint)).isBetween(28000L, 28800L);
        return new Session(cookie, prefix() + fingerprint, prefix() + "idle:" + fingerprint, id);
    }
    private void me(Session session, boolean interaction, int expected) throws Exception {
        var request = get("/api/auth/me").cookie(session.cookie());
        if (interaction) request.header("X-User-Activity", "1");
        mvc.perform(request).andExpect(status().is(expected));
    }
    private String csrf() throws Exception {
        return mapper.readTree(mvc.perform(get("/api/auth/csrf")).andReturn().getResponse().getContentAsString()).path("token").asText();
    }
    private String prefix() { return environment.getRequiredProperty("app.security.token-prefix"); }
    private record Session(MockCookie cookie, String absolute, String idle, String username) { }
}
