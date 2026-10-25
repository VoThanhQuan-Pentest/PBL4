package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.service.EmailOtpService;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Opt-in finite lab trials. SMTP is mocked; these are not real-user error estimates. */
@EnabledIfSystemProperty(named = "confirmation.trials.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false", "siem.prevention.enabled=false",
        "siem.security-events.enabled=false", "management.health.mail.enabled=false", "logging.level.AUDIT=OFF",
        "app.sensitive-action-confirmation.enabled=true"})
class SensitiveActionTrialIntegrationTest extends ContainerizedIntegrationTest {
    static final int OWNERS = bounded("confirmation.trials.owners", 20, 5000);
    static final int INVALID = bounded("confirmation.trials.invalid", 12, 2000);
    static final String CURRENT = "CurrentPassword1!", NEXT = "ReplacementPassword2!";
    static final String[] OPERATIONS = {"PASSWORD_CHANGE", "EMAIL_CHANGE"};
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired SensitiveActionConfirmationRepository actions;
    @Autowired PasswordEncoder encoder;
    @Autowired EmailOtpService otp;
    @Autowired JwtTokenService jwt;
    @Autowired RedisTokenStore tokens;
    @MockitoBean JavaMailSender mail;
    final Map<String, String> delivered = new ConcurrentHashMap<>();
    final List<Map<String, Object>> outcomes = new ArrayList<>();
    final Map<String, List<Double>> executionMillis = new LinkedHashMap<>();
    String seedHash;

    static int bounded(String name, int fallback, int maximum) {
        int value = Integer.getInteger(name, fallback);
        if (value < 1 || value > maximum) throw new IllegalArgumentException("bounded trial count required");
        return value;
    }
    static String id(int operation, int ordinal) { return "otp-trial-" + operation + "-" + ordinal; }
    @DynamicPropertySource static void trialPolicy(DynamicPropertyRegistry registry) {
        registry.add("app.sensitive-action-confirmation.account-allowlist", () -> IntStream.range(0, 2)
                .mapToObj(op -> IntStream.range(0, OWNERS + INVALID + 2).mapToObj(i -> id(op, i)).collect(Collectors.joining(",")))
                .collect(Collectors.joining(",")));
    }

    @Test @Timeout(8400)
    void recordsOperationDenominatorsAndImmutableNegativeControls() throws Exception {
        Path report = Path.of(System.getProperty("confirmation.trials.output")).toAbsolutePath();
        if (Files.exists(report)) throw new IllegalStateException("never overwrite prior trial evidence");
        Files.createFile(report, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        doAnswer(invocation -> {
            SimpleMailMessage message = invocation.getArgument(0);
            var matcher = Pattern.compile("\\b\\d{6}\\b").matcher(message.getText());
            assertThat(matcher.find()).isTrue();
            delivered.put(message.getTo()[0], matcher.group());
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
        seedHash = encoder.encode(CURRENT);
        boolean completed = false;
        long start = System.nanoTime();
        try {
            write(report, start, false); // Freeze scenario/count declarations before executing trials.
            for (int operation = 0; operation < 2; operation++) {
                for (int i = 0; i < OWNERS + INVALID + 2; i++) {
                    String scenario = i < OWNERS ? "OWNER_VALID_PROOF" : i < OWNERS + INVALID
                            ? new String[]{"WRONG_CODE", "OTHER_SESSION", "EXPIRED", "AUTH_VERSION_CHANGED"}[(i - OWNERS) % 4]
                            : i == OWNERS + INVALID ? "OWNER_WITHOUT_PROOF_CONTROL" : "SESSION_AND_MAILBOX_COMPROMISED_CONTROL";
                    trial(operation, i, scenario);
                    if ((i + 1) % 20 == 0) {
                        write(report, start, false);
                        clearInvocations(mail);
                        System.out.println("OTP_TRIAL_PROGRESS operation=" + OPERATIONS[operation] + " completed=" + (i + 1));
                    }
                }
            }
            completed = true;
        } finally {
            write(report, start, completed);
        }
    }

    void trial(int operation, int ordinal, String scenario) throws Exception {
        long trialStarted = System.nanoTime();
        boolean password = operation == 0;
        User user = fixture(id(operation, ordinal));
        String target = user.getId() + "-destination@example.test";
        // Actual local socket addresses distribute independent synthetic accounts;
        // the production login/OTP limits remain enabled and unchanged.
        int addressOrdinal = operation * (OWNERS + INVALID + 2) + ordinal + 1;
        InetAddress local = InetAddress.getByName("127." + (1 + addressOrdinal / 65536) + "."
                + (addressOrdinal / 256 % 256) + "." + (addressOrdinal % 256));
        try (HttpClient http = HttpClient.newBuilder().localAddress(local)
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build()) {
            String token = session(user);
            String csrf = json.readTree(request(http, token, null, "GET", "/api/auth/csrf", null).body()).path("token").asText();
            Object payload = password ? Map.of("operation", OPERATIONS[operation], "password",
                    Map.of("current_password", CURRENT, "new_password", NEXT, "confirm_password", NEXT))
                    : Map.of("operation", OPERATIONS[operation], "profile", Map.of("ho_ten", "Lab owner", "email", target, "sdt", ""));
            var preparation = request(http, token, csrf, "POST", "/api/profile/action-confirmations", payload);
            assertThat(preparation.statusCode()).as("preparation %s", scenario).isEqualTo(200);
            String challengeId = json.readTree(preparation.body()).path("id").asText();
            String code = delivered.remove(user.getEmail());
            String destinationCode = "";
            if (!password) {
                var destination = request(http, token, csrf, "POST", "/api/profile/email/otp", Map.of("email", target));
                assertThat(destination.statusCode()).isEqualTo(200);
                destinationCode = delivered.remove(target);
            }
            if (scenario.equals("WRONG_CODE")) code = "000000".equals(code) ? "111111" : "000000";
            if (scenario.equals("OTHER_SESSION")) token = session(user);
            if (scenario.equals("OWNER_WITHOUT_PROOF_CONTROL")) code = "";
            if (scenario.equals("EXPIRED")) {
                var pending = actions.findById(challengeId).orElseThrow();
                pending.setExpiresAt(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1)); actions.saveAndFlush(pending);
            }
            if (scenario.equals("AUTH_VERSION_CHANGED")) {
                user.setAuthVersion(1L); users.saveAndFlush(user);
            }
            String path = "/api/profile/action-confirmations/" + challengeId + "/execute";
            long start = System.nanoTime();
            var execution = request(http, token, csrf, "POST", path,
                    Map.of("confirmation_code", code, "destination_otp_code", destinationCode));
            double millis = (System.nanoTime() - start) / 1e6;
            executionMillis.computeIfAbsent(OPERATIONS[operation] + "/" + scenario, key -> new ArrayList<>()).add(millis);
            User after = users.findById(user.getId()).orElseThrow();
            boolean committed = actions.findById(challengeId).orElseThrow().getState().equals("COMMITTED");
            boolean valid = scenario.equals("OWNER_VALID_PROOF") || scenario.equals("SESSION_AND_MAILBOX_COMPROMISED_CONTROL");
            int expectedStatus = valid ? 200 : scenario.equals("AUTH_VERSION_CHANGED") ? 401
                    : scenario.equals("OTHER_SESSION") || scenario.equals("EXPIRED") ? 409 : 400;
            boolean correct = committed == valid && execution.statusCode() == expectedStatus && (valid ? execution.statusCode() == 200
                    && (password ? encoder.matches(NEXT, after.getPassword()) && after.getAuthVersion() == 1
                            && after.getEmail().equals(user.getEmail())
                    : after.getEmail().equals(target) && after.getPassword().equals(seedHash)
                            && after.getAuthVersion().equals(user.getAuthVersion()))
                    : after.getPassword().equals(seedHash) && after.getEmail().equals(user.getEmail())
                            && after.getAuthVersion().equals(user.getAuthVersion()) && after.getHoTen().equals(user.getHoTen()));
            boolean replaySafe = true;
            if (valid) {
                var replay = request(http, token, csrf, "POST", path, Map.of("confirmation_code", code, "destination_otp_code", destinationCode));
                User replayed = users.findById(user.getId()).orElseThrow();
                replaySafe = replay.statusCode() == (password ? 401 : 200)
                        && replayed.getPassword().equals(after.getPassword()) && replayed.getEmail().equals(after.getEmail())
                        && replayed.getAuthVersion().equals(after.getAuthVersion())
                        && replayed.getEmailVerifiedAt().equals(after.getEmailVerifiedAt()) && replayed.getHoTen().equals(after.getHoTen());
            }
            outcomes.add(Map.of("operation", OPERATIONS[operation], "scenario", scenario, "ordinal", ordinal,
                    "http_status", execution.statusCode(), "committed", committed, "correct", correct, "replay_safe", replaySafe,
                    "trial_seconds", (System.nanoTime() - trialStarted) / 1e9));
            assertThat(correct && replaySafe).as("trial %s %s ordinal=%s", OPERATIONS[operation], scenario, ordinal).isTrue();
        }
    }

    User fixture(String id) {
        String email = id + "@example.test";
        otp.sendOtp(EmailOtpService.PURPOSE_REGISTER, email);
        otp.verifyOtp(EmailOtpService.PURPOSE_REGISTER, email, delivered.remove(email));
        User user = new User(); user.setId(id); user.setUsername(id); user.setEmail(email);
        user.setEmailVerifiedAt(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1)); user.setAuthVersion(0L);
        user.setPassword(seedHash); user.setRole("CUSTOMER"); user.setHoTen("Lab owner");
        user.setStatus("Hoat dong"); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }
    String session(User user) {
        // Fixture authentication setup; every HTTP operation still verifies JWT,
        // Redis session presence, DB authVersion and CSRF through the real filters.
        String token = jwt.generateToken(new CurrentUserPrincipal(user));
        tokens.save(token, user.getUsername(), jwt.getExpirationSeconds());
        return token;
    }
    HttpResponse<String> request(HttpClient http, String token, String csrf, String method, String path, Object body) throws Exception {
        // Follow the existing HTTP integration client's per-mutation CSRF refresh.
        if (body != null) {
            var fresh = request(http, token, null, "GET", "/api/auth/csrf", null);
            assertThat(fresh.statusCode()).isEqualTo(200);
            csrf = json.readTree(fresh.body()).path("token").asText();
        }
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(20)).header("Authorization", "Bearer " + token);
        if (body == null) request.method(method, HttpRequest.BodyPublishers.noBody());
        else request.header("Content-Type", "application/json").header("X-XSRF-TOKEN", csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    void write(Path path, long start, boolean completed) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", completed ? "CONTROLLED_TRIALS_COMPLETE" : "PARTIAL_NOT_GATE_PASS");
        result.put("scope", "FINITE_SYNTHETIC_LAB_REAL_HTTP_MYSQL_REDIS_MOCK_SMTP");
        result.put("planned_eligible_owners_per_operation", OWNERS);
        result.put("planned_invalid_proofs_per_operation", INVALID);
        result.put("independent_account_per_trial", true);
        result.put("scenario_assignment", "owner prefix; four invalid-proof scenarios round-robin; missing-proof owner and compromised-mailbox controls last");
        result.put("statistical_generalization", "NOT_ESTABLISHED_SYNTHETIC_NOT_REAL_USER_FALSE_BLOCK_RATE");
        result.put("smtp_verified", false);
        result.put("elapsed_seconds", (System.nanoTime() - start) / 1e9);
        result.put("outcomes", outcomes);
        Map<String, Object> timings = new LinkedHashMap<>();
        executionMillis.forEach((name, values) -> {
            List<Double> sorted = values.stream().sorted().toList();
            timings.put(name, Map.of("n", sorted.size(), "p95_ms", sorted.get((int) Math.ceil(.95 * sorted.size()) - 1),
                    "maximum_ms", sorted.getLast()));
        });
        result.put("execution_latency_excludes_smtp_and_human", timings);
        byte[] bytes = json.writeValueAsBytes(result);
        Path temporary = Files.createTempFile(path.getParent(), ".pending-otp-trials-", ".json",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        try (FileChannel directory = FileChannel.open(path.getParent(), StandardOpenOption.READ)) { directory.force(true); }
    }
}
