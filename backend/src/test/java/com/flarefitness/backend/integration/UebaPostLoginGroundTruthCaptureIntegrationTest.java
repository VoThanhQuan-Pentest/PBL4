package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.ProfileEmailOtpRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.siem.PostLoginBehaviorFeatures;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
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
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Independent lab labels, real HTTP/JWT/database/OTP verification; mail never leaves the test. */
@EnabledIfSystemProperty(named = "postlogin.groundtruth.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false",
        "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
        "app.security.trusted-proxy-cidrs=", "logging.level.AUDIT=OFF", "management.health.mail.enabled=false"
})
class UebaPostLoginGroundTruthCaptureIntegrationTest extends ContainerizedIntegrationTest {
    @LocalServerPort private int port;
    @Autowired private ObjectMapper json;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private SiemSecurityEventRepository events;
    @MockitoBean private JavaMailSender mail;
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    private final Map<String, String> deliveredCodes = new ConcurrentHashMap<>();
    private final Set<String> excluded = ConcurrentHashMap.newKeySet();
    private final List<Map<String, Object>> snapshots = new ArrayList<>();
    private final List<Map<String, Object>> observations = new ArrayList<>();
    private final List<Map<String, Object>> outcomes = new ArrayList<>();
    private long lastRequest;
    private int requests;

    record Plan(String caseId, String pairId, String operation, String actorRole,
                String capability, boolean validProof, boolean parallelSession) { }

    @Test @Timeout(150)
    void capturesIndependentRolesWithoutPretendingNewMailboxProofIdentifiesTheOwner() throws Exception {
        Path repo = Path.of("").toAbsolutePath().normalize();
        if (!Files.isRegularFile(repo.resolve("backend/pom.xml"))) repo = repo.getParent();
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(repo,
                System.getProperty("postlogin.groundtruth.output"));
        List<Plan> plans = plans();
        assertThat(plans).hasSize(10);
        // This durable oracle exists before the first login. No response/score determines these labels.
        String manifestHash = publish(output, "label-manifest.private.json", Map.of(
                "version", "owned-http-postlogin-label-protocol-v1", "sealed_at", Instant.now().toString(),
                "provenance", "OWNED_CONTROLLED_RESEARCH_NOT_REAL_WORLD_ATTACKS", "plans", plans,
                "label_rule", "OWNER=AUTHORIZED_OWNER_ACTION; NONOWNER=CONTROLLED_UNAUTHORIZED_ACTION"));
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var matcher = Pattern.compile("(?<!\\d)\\d{6}(?!\\d)").matcher(message.getText());
            if (!matcher.find()) throw new IllegalStateException("Expected one locally delivered OTP");
            String code = matcher.group();
            excluded.add(code);
            deliveredCodes.put(message.getTo()[0], code);
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
        Instant started = Instant.now();
        for (Plan plan : plans) capture(plan);
        assertThat(snapshots).hasSize(10);
        assertThat(snapshots).allSatisfy(row -> {
            assertThat(row.get("authenticated_session_covered")).isEqualTo(true);
            assertThat(row.get("same_session_login_observed")).isEqualTo(true);
        });
        long authorized = outcomes.stream().filter(row -> row.get("actor_role").equals("OWNER")).count();
        long unauthorizedCommitted = outcomes.stream().filter(row -> row.get("actor_role").equals("NONOWNER")
                && row.get("account_mutated").equals(true)).count();
        long rejected = outcomes.stream().filter(row -> row.get("http_status").equals(400)).count();
        assertThat(authorized).isEqualTo(5);
        assertThat(unauthorizedCommitted).isEqualTo(3);
        assertThat(rejected).isEqualTo(4);
        assertThat(requests).isLessThanOrEqualTo(100);
        Map<String, String> files = Map.of(
                "server-observations.private.json", publish(output, "server-observations.private.json", observations),
                "before-attempt-features.private.json", publish(output, "before-attempt-features.private.json", snapshots),
                "outcomes-labels.private.json", publish(output, "outcomes-labels.private.json", outcomes),
                "label-manifest.private.json", manifestHash);
        assertThat(sha256(Files.readAllBytes(output.resolve("label-manifest.private.json")))).isEqualTo(manifestHash);
        Map<String, Object> receipt = new LinkedHashMap<>();
        receipt.put("status", "CAPTURE_PASS_TRAINING_NOT_ADMITTED");
        receipt.put("files_sha256", files);
        receipt.put("pairs", 5); receipt.put("sensitive_attempts", 10); receipt.put("http_requests", requests);
        receipt.put("independent_labels_sealed_before_first_http", true);
        receipt.put("real_http_jwt_mysql_redis_otp_verifier", true);
        receipt.put("mail_transport", "IN_MEMORY_ONLY"); receipt.put("otp_verifier_mocked", false);
        receipt.put("first_attempts_before_account_mutations", true);
        receipt.put("current_outcome_and_future_invariance", true);
        receipt.put("preexisting_auth_rejections", rejected);
        receipt.put("controlled_nonowner_account_mutations", unauthorizedCommitted);
        receipt.put("same_ip_and_ua_within_pair", true);
        receipt.put("rate_limits_changed", false);
        receipt.put("prior_window_history", "COLD_ONLY_NO_POPULATION_QUALITY_CLAIM");
        receipt.put("owner_identity_proof_in_features", "NOT_OBSERVED");
        receipt.put("new_fit_calls", 0); receipt.put("holdout_scored", false); receipt.put("auto_containment", false);
        receipt.put("elapsed_seconds", Duration.between(started, Instant.now()).toMillis() / 1000.0);
        String receiptHash = publish(output, "capture.receipt.private.json", receipt);
        publish(output, "capture.commit.private.json", Map.of("receipt", "capture.receipt.private.json", "receipt_sha256", receiptHash));
    }

    private List<Plan> plans() {
        var result = new ArrayList<Plan>();
        for (int pair = 0; pair < 5; pair++) {
            boolean email = pair >= 2;
            for (String role : List.of("OWNER", "NONOWNER")) {
                result.add(new Plan("case-" + result.size(), "pair-" + pair,
                        email ? "EMAIL_CHANGE" : "PASSWORD_CHANGE", role,
                        role.equals("OWNER") ? "OWNER_SESSION_AND_CREDENTIALS" :
                                email || pair == 1 ? "COPIED_TEST_SESSION_AND_NEW_MAILBOX_ONLY" : "COPIED_TEST_SESSION_AND_PASSWORD",
                        pair != 1 && pair != 3, pair == 4));
            }
        }
        return List.copyOf(result);
    }

    private void capture(Plan plan) throws Exception {
        String initial = "GroundTruthInitial#" + UUID.randomUUID();
        String replacement = "GroundTruthReplacement#" + UUID.randomUUID();
        String targetEmail = UUID.randomUUID() + "@example.test";
        excluded.addAll(List.of(initial, replacement, targetEmail));
        User account = customer(initial);
        String oldEmail = account.getEmail();
        LocalDateTime from = LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1);
        String localIp = "127.0.0." + (2 + Integer.parseInt(plan.pairId().substring(5)));
        try (Client owner = new Client(localIp); Client actor = new Client(localIp); Client parallel = new Client(localIp)) {
            login(owner, account, initial);
            if (plan.parallelSession()) login(parallel, account, initial);
            Client active = plan.actorRole().equals("OWNER") ? owner : actor;
            if (active == actor) {
                // Controlled transfer happens only inside the lab; no raw session is published.
                for (var cookie : owner.cookies.getCookieStore().getCookies()) actor.cookies.getCookieStore().add(base(), cookie);
            }
            send(active, "GET", "/api/profile", null, 200);
            csrf(active);
            int expected = plan.validProof() ? plan.operation().equals("PASSWORD_CHANGE") ? 204 : 200 : 400;
            if (plan.operation().equals("EMAIL_CHANGE")) {
                send(active, "POST", "/api/profile/email/otp", new ProfileEmailOtpRequest(targetEmail), 200);
                String code = deliveredCodes.get(targetEmail);
                assertThat(code != null).isTrue();
                String submitted = plan.validProof() ? code : code.equals("000000") ? "999999" : "000000";
                csrf(active);
                send(active, "PUT", "/api/profile", new UpdateProfileRequest("Owned controlled fixture", targetEmail,
                        "093" + String.format("%07d", Integer.parseInt(plan.caseId().substring(5))), submitted), expected);
            } else {
                send(active, "PUT", "/api/profile/password", new ChangePasswordRequest(
                        plan.validProof() ? initial : "IncorrectCurrentForBothRoles", replacement, replacement), expected);
            }
            User after = users.findById(account.getId()).orElseThrow();
            boolean changed = plan.operation().equals("EMAIL_CHANGE") ? targetEmail.equals(after.getEmail())
                    : passwords.matches(replacement, after.getPassword());
            assertThat(changed).isEqualTo(plan.validProof());
            if (!changed) {
                assertThat(after.getEmail()).isEqualTo(oldEmail);
                assertThat(passwords.matches(initial, after.getPassword())).isTrue();
            }
            List<SiemSecurityEvent> evidence = events.findAccountEvidence(account.getId(), from,
                    LocalDateTime.now(ZoneOffset.UTC).plusSeconds(1), PageRequest.of(0, 100)).getContent().stream()
                    .sorted(Comparator.comparing(SiemSecurityEvent::getEventTimestamp)).toList();
            var attempts = evidence.stream().filter(e -> e.getEventType().equals("SENSITIVE_ACTION_ATTEMPT")).toList();
            assertThat(attempts).hasSize(1);
            SiemSecurityEvent attempt = attempts.get(0);
            var snapshot = PostLoginBehaviorFeatures.beforeAttempt(attempt, evidence);
            var before = evidence.stream().filter(e -> e.getEventTimestamp().isBefore(attempt.getEventTimestamp())).toList();
            assertThat(PostLoginBehaviorFeatures.beforeAttempt(attempt, before)).isEqualTo(snapshot);
            assertThat(snapshot.values().get(2)).isEqualTo(1.0);
            assertThat(snapshot.values().get(3)).isEqualTo(1.0);
            assertThat(snapshot.values().get(14)).isEqualTo(plan.parallelSession() ? 1.0 : 0.0);
            var actions = evidence.stream().filter(e -> e.getEventType().equals("DOMAIN_ACTION")).toList();
            assertThat(actions).hasSize(changed ? 1 : 0);
            for (var action : actions) {
                assertThat(action.getSessionPseudonym()).isEqualTo(attempt.getSessionPseudonym());
                assertThat(action.getEventTimestamp()).isAfter(attempt.getEventTimestamp());
            }
            snapshots.add(Map.of("case_id", plan.caseId(), "feature_version", snapshot.version(),
                    "feature_names", snapshot.names(), "values", snapshot.values(),
                    "as_of", attempt.getEventTimestamp().toInstant(ZoneOffset.UTC).toString(),
                    "input_event_ids", before.stream().map(e -> alias(e, evidence, plan)).toList(),
                    "authenticated_session_covered", true, "same_session_login_observed", true));
            for (var event : evidence) observations.add(sanitized(event, evidence, plan));
            outcomes.add(Map.of("case_id", plan.caseId(), "pair_id", plan.pairId(), "actor_role", plan.actorRole(),
                    "ground_truth", plan.actorRole().equals("OWNER") ? "AUTHORIZED_OWNER_ACTION" : "CONTROLLED_UNAUTHORIZED_ACTION",
                    "operation", plan.operation(), "http_status", expected, "account_mutated", changed,
                    "label_source", "SEALED_ROLE_MANIFEST"));
        }
    }

    private Map<String, Object> sanitized(SiemSecurityEvent event, List<SiemSecurityEvent> evidence, Plan plan) {
        var row = new LinkedHashMap<String, Object>();
        row.put("event_id", alias(event, evidence, plan)); row.put("account_id", "account-" + plan.caseId());
        row.put("event_type", event.getEventType()); row.put("action", event.getAction()); row.put("outcome", event.getOutcome());
        row.put("event_timestamp", event.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());
        row.put("telemetry_contract_version", event.getTelemetryContractVersion());
        row.put("session_pseudonym", event.getSessionPseudonym());
        row.put("session_issued_at", event.getSessionIssuedAt() == null ? null : event.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
        row.put("http_status", event.getHttpStatus()); row.put("endpoint_category", event.getEndpointCategory());
        return row;
    }

    private String alias(SiemSecurityEvent event, List<SiemSecurityEvent> evidence, Plan plan) {
        return plan.caseId() + "-event-" + evidence.indexOf(event);
    }

    private User customer(String password) {
        var user = new User(); String id = "gt-" + UUID.randomUUID().toString().replace("-", "");
        user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(password)); user.setAuthVersion(0L);
        user.setRole("CUSTOMER"); user.setHoTen("Owned ground truth fixture"); user.setEmail(id + "@example.test");
        user.setStatus("Hoat dong"); user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        excluded.add(id); excluded.add(user.getEmail());
        return users.saveAndFlush(user);
    }

    private void login(Client client, User user, String password) throws Exception {
        csrf(client);
        send(client, "POST", "/api/auth/login", Map.of("username", user.getUsername(), "password", password), 200);
        client.cookies.getCookieStore().getCookies().forEach(cookie -> excluded.add(cookie.getValue()));
    }

    private void csrf(Client client) throws Exception {
        client.csrf = json.readTree(send(client, "GET", "/api/auth/csrf", null, 200).body()).path("token").asText();
        excluded.add(client.csrf);
    }

    private HttpResponse<String> send(Client client, String method, String path, Object body, int expected) throws Exception {
        long delay = TimeUnit.MILLISECONDS.toNanos(210) - (System.nanoTime() - lastRequest);
        if (delay > 0) TimeUnit.NANOSECONDS.sleep(delay);
        lastRequest = System.nanoTime();
        assertThat(++requests).isLessThanOrEqualTo(100);
        var builder = HttpRequest.newBuilder(base().resolve(path)).timeout(Duration.ofSeconds(5))
                .header("User-Agent", "OwnedGroundTruthFixture/1.0");
        if (body == null) builder.method(method, HttpRequest.BodyPublishers.noBody());
        else builder.header("Content-Type", "application/json").header("X-XSRF-TOKEN", client.csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        var response = client.http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("%s %s", method, path).isEqualTo(expected);
        return response;
    }

    private URI base() { return URI.create("http://127.0.0.1:" + port); }

    private String publish(Path output, String name, Object document) throws Exception {
        byte[] bytes = json.writeValueAsBytes(document);
        assertThat(bytes.length).isLessThanOrEqualTo(512 * 1024);
        String text = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        for (String secret : excluded) assertThat(text.contains(secret)).as("Private value excluded from %s", name).isFalse();
        try (FileChannel channel = FileChannel.open(output.resolve(name), Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        try (FileChannel directory = FileChannel.open(output, StandardOpenOption.READ)) { directory.force(true); }
        return sha256(bytes);
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static final class Client implements AutoCloseable {
        final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        final HttpClient http;
        String csrf;
        Client(String localAddress) throws Exception {
            http = HttpClient.newBuilder().cookieHandler(cookies).localAddress(InetAddress.getByName(localAddress))
                    .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
        }
        @Override public void close() { http.close(); }
    }
}
