package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.SensitiveActionConfirmationService;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Real localhost HTTP/JWT/CSRF/MySQL/Redis; SMTP is captured in memory only. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false", "siem.prevention.enabled=false",
        "siem.security-events.enabled=false", "management.health.mail.enabled=false", "logging.level.AUDIT=OFF",
        "app.sensitive-action-confirmation.enabled=true",
        "app.sensitive-action-confirmation.account-allowlist=confirmation-password,confirmation-email,confirmation-mail-fault,confirmation-db-fault"})
class SensitiveActionConfirmationIntegrationTest extends ContainerizedIntegrationTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired EmailOtpService otp;
    @Autowired SensitiveActionConfirmationRepository actions;
    @Autowired SensitiveActionConfirmationService confirmations;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean JavaMailSender mail;
    final Map<String, String> delivered = new ConcurrentHashMap<>();
    static final String CURRENT = "CurrentPassword1!", REPLACEMENT = "ReplacementPassword2!";

    void captureMail() {
        doAnswer(invocation -> {
            SimpleMailMessage message = invocation.getArgument(0);
            var matcher = Pattern.compile("\\b\\d{6}\\b").matcher(message.getText());
            assertThat(matcher.find()).isTrue();
            delivered.put(message.getTo()[0], matcher.group());
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    Map<String, Object> passwordRequest() {
        return Map.of("operation", "PASSWORD_CHANGE", "password", Map.of("current_password", CURRENT,
                "new_password", REPLACEMENT, "confirm_password", REPLACEMENT));
    }

    @Test @Timeout(120)
    void failedMailLeavesNoUsableProofAndASeparateChallengeCanRecover() throws Exception {
        captureMail();
        User user = fixture("confirmation-mail-fault");
        try (Client owner = new Client()) {
            login(owner, user);
            doThrow(new MailSendException("controlled test transport failure")).when(mail).send(any(SimpleMailMessage.class));
            send(owner, "POST", "/api/profile/action-confirmations", passwordRequest(), 400);
            var failed = actions.findAll().stream().filter(a -> a.getUserId().equals(user.getId())).findFirst().orElseThrow();
            assertThat(failed.getState()).isEqualTo("PENDING");
            assertThat(users.findById(user.getId()).orElseThrow().getPassword()).isEqualTo(user.getPassword());
            captureMail();
            var fresh = body(send(owner, "POST", "/api/profile/action-confirmations", passwordRequest(), 200));
            String code = delivered.get(user.getEmail());
            send(owner, "POST", "/api/profile/action-confirmations/" + failed.getId() + "/execute",
                    Map.of("confirmation_code", code), 400);
            send(owner, "POST", "/api/profile/action-confirmations/" + fresh.path("id").asText() + "/execute",
                    Map.of("confirmation_code", code), 200);
            assertThat(encoder.matches(REPLACEMENT, users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
        }
    }

    @Test @Timeout(120)
    void databaseCommitFailureRollsBackMutationAndConsumedProofCannotBeReplayed() throws Exception {
        captureMail();
        User user = fixture("confirmation-db-fault");
        try (Client owner = new Client()) {
            login(owner, user);
            var prepared = body(send(owner, "POST", "/api/profile/action-confirmations", passwordRequest(), 200));
            String id = prepared.path("id").asText();
            String code = delivered.get(user.getEmail());
            jdbc.execute("ALTER TABLE sensitive_action_confirmations ADD CONSTRAINT lab_reject_confirmation_commit "
                    + "CHECK (user_id <> 'confirmation-db-fault' OR state <> 'COMMITTED')");
            try {
                // Hibernate 7 translates this CHECK rejection to the API's
                // existing, sanitized DataIntegrityViolationException contract.
                var failure = send(owner, "POST", "/api/profile/action-confirmations/" + id + "/execute", Map.of("confirmation_code", code), 400);
                assertThat(body(failure).path("code").asText()).isEqualTo("DATA_CONSTRAINT_VIOLATION");
            } finally {
                jdbc.execute("ALTER TABLE sensitive_action_confirmations DROP CHECK lab_reject_confirmation_commit");
            }
            User unchanged = users.findById(user.getId()).orElseThrow();
            assertThat(unchanged.getPassword()).isEqualTo(user.getPassword());
            assertThat(unchanged.getAuthVersion()).isEqualTo(user.getAuthVersion());
            var pending = actions.findById(id).orElseThrow();
            assertThat(pending.getState()).isEqualTo("PENDING");
            // SQL rollback cannot restore a consumed Redis proof or session revocation: fail closed.
            var replay = raw(owner, "POST", "/api/profile/action-confirmations/" + id + "/execute",
                    Map.of("confirmation_code", code), csrf(owner));
            assertThat(replay.statusCode()).isIn(400, 401);
            pending.setExpiresAt(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1));
            actions.saveAndFlush(pending);
            confirmations.cleanExpired();
            var expired = actions.findById(id).orElseThrow();
            assertThat(expired.getState()).isEqualTo("EXPIRED");
            assertThat(expired.getPasswordHash()).isNull();
        }
    }

    @Test @Timeout(180)
    void mandatoryProofBindsAccountSessionAndPayloadAndMutatesExactlyOnce() throws Exception {
        doAnswer(invocation -> {
            SimpleMailMessage message = invocation.getArgument(0);
            var matcher = Pattern.compile("\\b\\d{6}\\b").matcher(message.getText());
            assertThat(matcher.find()).isTrue();
            delivered.put(message.getTo()[0], matcher.group());
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
        User passwordUser = fixture("confirmation-password");
        User emailUser = fixture("confirmation-email");
        try (Client owner = new Client(); Client otherSession = new Client(owner.localAddress); Client emailOwner = new Client()) {
            login(owner, passwordUser); login(otherSession, passwordUser); login(emailOwner, emailUser);
            var policy = body(send(owner, "GET", "/api/profile/action-confirmations/policy", null, 200));
            assertThat(policy.path("required").asBoolean()).isTrue();
            assertThat(policy.path("contact_available").asBoolean()).isTrue();
            assertThat(policy.has("contactAvailable")).isFalse();
            var passwordBody = Map.of("current_password", CURRENT, "new_password", REPLACEMENT, "confirm_password", REPLACEMENT);
            assertThat(json.readTree(send(owner, "PUT", "/api/profile/password", passwordBody, 409).body()).path("code").asText())
                    .isEqualTo("ACTION_CONFIRMATION_REQUIRED");
            var prepared = body(send(owner, "POST", "/api/profile/action-confirmations",
                    Map.of("operation", "PASSWORD_CHANGE", "password", passwordBody), 200));
            String id = prepared.path("id").asText(); String code = delivered.get(passwordUser.getEmail());
            assertThat(prepared.path("expires_at").asText()).isNotBlank();
            assertThat(prepared.path("confirmation_email_masked").asText()).contains("***@");
            assertThat(prepared.path("policy_id").asText()).isEqualTo(com.flarefitness.backend.service.SensitiveActionPolicy.ID);
            assertThat(prepared.has("expiresAt")).isFalse();
            String execute = "/api/profile/action-confirmations/" + id + "/execute";
            send(otherSession, "POST", execute, Map.of("confirmation_code", code), 409);
            send(emailOwner, "POST", execute, Map.of("confirmation_code", code), 409);
            send(owner, "POST", execute, Map.of("confirmation_code", wrong(code)), 400);
            assertThat(encoder.matches(CURRENT, users.findById(passwordUser.getId()).orElseThrow().getPassword())).isTrue();
            // Concurrent executions use one immutable challenge and one account lock.
            String csrf = csrf(owner);
            try (var threads = Executors.newFixedThreadPool(2)) {
                var first = threads.submit(() -> raw(owner, "POST", execute, Map.of("confirmation_code", code), csrf));
                var second = threads.submit(() -> raw(owner, "POST", execute, Map.of("confirmation_code", code), csrf));
                int firstStatus = first.get().statusCode(), secondStatus = second.get().statusCode();
                assertThat(firstStatus).isIn(200, 401, 409);
                assertThat(secondStatus).isIn(200, 401, 409);
                assertThat(firstStatus == 200 || secondStatus == 200).isTrue();
            }
            User changed = users.findById(passwordUser.getId()).orElseThrow();
            assertThat(changed.getAuthVersion()).isEqualTo(passwordUser.getAuthVersion() + 1);
            assertThat(encoder.matches(REPLACEMENT, changed.getPassword())).isTrue();

            String destination = "destination@example.test";
            var profile = Map.of("ho_ten", "Confirmed owner", "email", destination, "sdt", "0930000111");
            send(emailOwner, "PUT", "/api/profile", profile, 409);
            var emailChallenge = body(send(emailOwner, "POST", "/api/profile/action-confirmations",
                    Map.of("operation", "EMAIL_CHANGE", "profile", profile), 200));
            String emailCode = delivered.get(emailUser.getEmail());
            assertThat(delivered).doesNotContainKey(destination);
            send(emailOwner, "POST", "/api/profile/email/otp", Map.of("email", destination), 200);
            String emailExecute = "/api/profile/action-confirmations/" + emailChallenge.path("id").asText() + "/execute";
            send(emailOwner, "POST", emailExecute,
                    Map.of("confirmation_code", wrong(emailCode), "destination_otp_code", delivered.get(destination)), 400);
            assertThat(users.findById(emailUser.getId()).orElseThrow().getEmail()).isEqualTo(emailUser.getEmail());
            var result = body(send(emailOwner, "POST", emailExecute,
                    Map.of("confirmation_code", emailCode, "destination_otp_code", delivered.get(destination),
                            "email", "payload-injection@example.test"), 200));
            assertThat(result.path("profile").path("email").asText()).isEqualTo(destination);
            send(emailOwner, "POST", emailExecute, Map.of("confirmation_code", emailCode), 200);
            assertThat(users.findById(emailUser.getId()).orElseThrow().getEmail()).isEqualTo(destination);
        }
    }

    User fixture(String id) {
        // The superclass tests also run in the dependency-fault subclass.
        // Reset only this fixture's proof rows and use a fresh verified mailbox.
        jdbc.update("DELETE FROM sensitive_action_confirmations WHERE user_id=?", id);
        String email = id + "-" + java.util.UUID.randomUUID() + "@example.test";
        otp.sendOtp(EmailOtpService.PURPOSE_REGISTER, email);
        otp.verifyOtp(EmailOtpService.PURPOSE_REGISTER, email, delivered.get(email));
        User user = new User(); user.setId(id); user.setUsername(id); user.setEmail(email);
        user.setEmailVerifiedAt(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1));
        user.setPassword(encoder.encode(CURRENT)); user.setRole("CUSTOMER"); user.setHoTen("Confirmation lab owner");
        user.setStatus("Hoat dong"); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }
    void login(Client client, User user) throws Exception {
        send(client, "POST", "/api/auth/login", Map.of("username", user.getUsername(), "password", CURRENT), 200);
    }
    JsonNode body(HttpResponse<String> response) throws Exception { return json.readTree(response.body()); }
    String wrong(String code) { return "000000".equals(code) ? "111111" : "000000"; }
    String csrf(Client client) throws Exception {
        var response = raw(client, "GET", "/api/auth/csrf", null, null);
        assertThat(response.statusCode()).isEqualTo(200);
        return body(response).path("token").asText();
    }
    HttpResponse<String> send(Client client, String method, String path, Object payload, int expected) throws Exception {
        var response = raw(client, method, path, payload, payload == null ? null : csrf(client));
        // Do not print request/response bodies: they may include OTPs or private profile data.
        assertThat(response.statusCode()).as("%s %s", method, path).isEqualTo(expected);
        return response;
    }
    HttpResponse<String> raw(Client client, String method, String path, Object payload, String csrf) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(15));
        if (payload == null) request.method(method, HttpRequest.BodyPublishers.noBody());
        else request.header("Content-Type", "application/json").header("X-XSRF-TOKEN", csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(payload)));
        return client.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    static class Client implements AutoCloseable {
        static final java.util.concurrent.atomic.AtomicInteger NEXT_ADDRESS = new java.util.concurrent.atomic.AtomicInteger(1);
        final java.net.InetAddress localAddress;
        final HttpClient http;
        Client() throws java.net.UnknownHostException {
            this(address(NEXT_ADDRESS.getAndIncrement()));
        }
        Client(java.net.InetAddress address) {
            localAddress = address;
            http = HttpClient.newBuilder().localAddress(address)
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        }
        static java.net.InetAddress address(int ordinal) throws java.net.UnknownHostException {
            return java.net.InetAddress.getByAddress(new byte[]{127, 2, (byte)(ordinal / 256), (byte)(ordinal % 256)});
        }
        public void close() { http.close(); }
    }
}
