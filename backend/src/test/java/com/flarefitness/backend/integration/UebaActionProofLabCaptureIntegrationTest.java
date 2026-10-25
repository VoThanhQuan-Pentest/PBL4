package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.ProfileEmailOtpRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.ops.PostLoginFeatureExport;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.ProfileService;
import com.flarefitness.backend.service.siem.PostLoginBehaviorFeatures;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import com.flarefitness.backend.service.siem.SecurityEventService;
import com.flarefitness.backend.integration.ActionProofCapturePlan.Plan;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Four real sensitive attempts only. Additional requests exercise the optional proof protocol. */
@EnabledIfSystemProperty(named = "postlogin.action-proof.capture.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false",
        "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
        "siem.security-events.action-proof-lab-enabled=true", "app.security.trusted-proxy-cidrs=",
        "logging.level.AUDIT=OFF", "management.health.mail.enabled=false"
})
@Import(ActionProofLabConfiguration.class)
class UebaActionProofLabCaptureIntegrationTest extends ContainerizedIntegrationTest {
    @LocalServerPort private int port;
    @Autowired private ObjectMapper json;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemUebaModelJobRepository jobs;
    @Autowired private EmailOtpService otp;
    @Autowired private JwtTokenService jwt;
    @Autowired private StringRedisTemplate redis;
    @Autowired private ActionProofLabConfiguration.Service proofs;
    @Autowired private ApplicationContext applicationContext;
    @MockitoBean private JavaMailSender mail;
    @MockitoBean private SecurityEventExportWorker rawOutboxFileSink;
    @MockitoSpyBean private SecurityEventService observedEvents;
    @MockitoSpyBean private ProfileService observedProfile;
    private final Map<String, String> delivered = new ConcurrentHashMap<>();
    private final Set<String> excluded = ConcurrentHashMap.newKeySet();
    private final AtomicReference<String> lastDeliveredTo = new AtomicReference<>();
    private final Map<String, Plan> byActor = new ConcurrentHashMap<>();
    private final List<Map<String, Object>> captures = new ArrayList<>();
    private final List<Map<String, Object>> outcomes = new ArrayList<>();
    private final Map<String, Object> controls = new LinkedHashMap<>();
    private long lastRequest;
    private int requests;

    record Owned(Plan plan, User user, String password, String replacement, String target, String anchor) { }
    record Grant(String challenge, String proof) { }

    @Test @Timeout(120)
    void protocolReadinessWithoutSensitiveActions() throws Exception {
        installLocalMail();
        var owned = fixture(new Plan("probe-0", "probe-only", "EMAIL_CHANGE", "OWNER", "PROTOCOL_READINESS_ONLY", "VERIFIED"));
        otp.sendOtp(EmailOtpService.PURPOSE_LAB_ACTION_PROOF, owned.anchor());
        otp.verifyOtp(EmailOtpService.PURPOSE_LAB_ACTION_PROOF, owned.anchor(), delivered.get(owned.anchor()));
        proofs.bindVerifiedFixture(owned.user().getId(), owned.anchor(), "a".repeat(64));
        assertThat(applicationContext.getBeansOfType(ActionProofLabConfiguration.Observer.class)).hasSize(1);
        try (var client = new Client("127.0.0.9")) {
            login(client, owned);
            Grant grant = grant(client, owned, true);
            assertThat(proofs.consume(binding(client, owned.user()), owned.plan().action(), owned.target(), grant.proof()).state()).isEqualTo("VERIFIED");
            post(client, "/api/lab/action-proof/verify", new ActionProofLabConfiguration.Verification(grant.challenge(),
                    delivered.get(owned.anchor())), null, 400);
            var adviceObserved = new AtomicBoolean();
            doAnswer(call -> {
                var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
                var evidence = (ActionProofLabConfiguration.Evidence) request.getAttribute(ActionProofLabConfiguration.EVIDENCE_ATTRIBUTE);
                assertThat(evidence != null && evidence.state().equals("NOT_OBSERVED")).isTrue();
                adviceObserved.set(true);
                return call.callRealMethod();
            }).when(observedProfile).updateProfile(anyString(), any(UpdateProfileRequest.class));
            // Same email: real body advice and existing profile persistence, zero sensitive attempts.
            post(client, "/api/profile", new UpdateProfileRequest("Owned protocol probe", owned.anchor(), "0930000099", null), null, 200);
            assertThat(adviceObserved.get()).isTrue();
        }
        var source = events.findAccountEvidence(owned.user().getId(), LocalDateTime.now(ZoneOffset.UTC).minusMinutes(5),
                LocalDateTime.now(ZoneOffset.UTC).plusSeconds(1), PageRequest.of(0, 100)).getContent();
        assertThat(source.stream().anyMatch(e -> "SENSITIVE_ACTION_ATTEMPT".equals(e.getEventType())
                || "DOMAIN_ACTION".equals(e.getEventType()))).isFalse();
    }

    @Test @Timeout(190)
    void capturesBoundChannelEvidenceBeforeFourUnchangedSensitiveActions() throws Exception {
        Path repo = Path.of("").toAbsolutePath().normalize();
        if (!Files.isRegularFile(repo.resolve("backend/pom.xml"))) repo = repo.getParent();
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(repo,
                System.getProperty("postlogin.action-proof.capture.output"));
        installLocalMail();
        boolean coverageControls = Boolean.getBoolean("postlogin.action-proof.capture.coverage-controls");
        List<Plan> plans = coverageControls ? ActionProofCapturePlan.coverageControls() : ActionProofCapturePlan.initialSignalCases();
        var fixtures = new ArrayList<Owned>(); var attestations = new ArrayList<Map<String, Object>>();
        for (Plan plan : plans) {
            Owned owned = fixture(plan); fixtures.add(owned); byActor.put(owned.user().getId(), plan);
            // Actual OTP receipt and verification precede the fixed trust binding and every scenario HTTP request.
            otp.sendOtp(EmailOtpService.PURPOSE_LAB_ACTION_PROOF, owned.anchor());
            otp.verifyOtp(EmailOtpService.PURPOSE_LAB_ACTION_PROOF, owned.anchor(), delivered.get(owned.anchor()));
            String attestation = sha((plan.caseId() + ":mailbox-control:" + UUID.randomUUID()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            proofs.bindVerifiedFixture(owned.user().getId(), owned.anchor(), attestation);
            attestations.add(Map.of("case_id", plan.caseId(), "control_attestation_sha256", attestation,
                    "real_otp_verified_before_binding", true, "bound_at", Instant.now().toString()));
        }
        String oracleHash = publish(output, "oracle.private.json", Map.of("plans", plans, "anchors", attestations,
                "sealed_at", Instant.now().toString(), "provenance", "CONTROLLED_LOCAL_RESEARCH_NOT_REAL_WORLD_ATTACKS"));
        long jobsBefore = jobs.count();
        doAnswer(call -> {
            call.callRealMethod();
            String actor = call.getArgument(1); Plan plan = byActor.get(actor);
            if (plan == null) return null;
            var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            var evidence = (ActionProofLabConfiguration.Evidence) request.getAttribute(ActionProofLabConfiguration.EVIDENCE_ATTRIBUTE);
            assertThat(evidence != null).isTrue();
            var context = events.findAccountEvidence(actor, LocalDateTime.now(ZoneOffset.UTC).minusMinutes(15),
                    LocalDateTime.now(ZoneOffset.UTC).plusSeconds(1), PageRequest.of(0, 200)).getContent();
            var attempts = context.stream().filter(e -> "SENSITIVE_ACTION_ATTEMPT".equals(e.getEventType())).toList();
            assertThat(attempts).hasSize(1);
            var attempt = attempts.get(0);
            assertThat(context.stream().anyMatch(e -> "DOMAIN_ACTION".equals(e.getEventType()))).isFalse();
            // These fixture accounts were created immediately before this capture;
            // no closed windows exist. Do not reconstruct these fields for old captures.
            var observed = PostLoginFeatureExport.fromObserved(attempt, context, List.of());
            var base = observed.postlogin();
            var names = new ArrayList<>(base.names()); names.addAll(ActionProofLabConfiguration.FEATURE_NAMES);
            var values = new ArrayList<>(base.values()); values.addAll(evidence.values());
            var row = new LinkedHashMap<String, Object>();
            row.put("case_id", plan.caseId()); row.put("feature_version", "postlogin-action-proof-lab-v2");
            row.put("feature_names", names); row.put("values", values);
            row.put("baseline_feature_names", AccountBehaviorFeatures.names(4)); row.put("baseline_features", observed.baselineFeatures());
            row.put("baseline_established", observed.baselineEstablished()); row.put("trusted_window_count", observed.trustedWindowCount());
            row.put("server_proof_state", evidence.state()); row.put("as_of", attempt.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());
            row.put("current_outcome_known", false); row.put("account_mutation_observed_at_capture", false);
            row.put("proof_stage", "SERVER_BODY_ADVICE_BEFORE_PROFILE_SERVICE");
            captures.add(row);
            return null;
        }).when(observedEvents).recordSensitiveActionAttempt(anyString(), anyString());
        Instant started = Instant.now();
        for (Owned owned : fixtures) execute(owned);
        assertThat(captures).hasSize(4); assertThat(outcomes).hasSize(4);
        assertThat(captures.stream().filter(row -> row.get("server_proof_state").equals("VERIFIED")).count()).isEqualTo(2);
        assertThat(jobs.count()).isEqualTo(jobsBefore);
        assertThat(sha(Files.readAllBytes(output.resolve("oracle.private.json")))).isEqualTo(oracleHash);
        Map<String, String> hashes = Map.of("oracle.private.json", oracleHash,
                "precommit.private.json", publish(output, "precommit.private.json", captures),
                "outcomes.private.json", publish(output, "outcomes.private.json", outcomes),
                "controls.private.json", publish(output, "controls.private.json", controls));
        var receipt = new LinkedHashMap<String, Object>();
        receipt.put("status", "PROOF_SIGNAL_OBSERVED_RESEARCH_ONLY"); receipt.put("files_sha256", hashes);
        receipt.put("pairs", 2); receipt.put("sensitive_attempts", 4); receipt.put("http_requests", requests);
        receipt.put("capture_scope", coverageControls ? "COVERAGE_CONTROLS" : "INITIAL_SIGNAL_CASES");
        receipt.put("authorized_proof_verified", captures.stream().filter(row -> row.get("server_proof_state").equals("VERIFIED")
                && plans.stream().anyMatch(p -> p.caseId().equals(row.get("case_id")) && p.role().equals("OWNER"))).count());
        receipt.put("controlled_nonowner_proof_not_verified", captures.stream().filter(row -> !row.get("server_proof_state").equals("VERIFIED")
                && plans.stream().anyMatch(p -> p.caseId().equals(row.get("case_id")) && p.role().equals("NONOWNER"))).count());
        receipt.put("legacy_sensitive_actions_accepted", 4); receipt.put("account_mutation_after_snapshot", true);
        receipt.put("real_http_jwt_mysql_redis_otp", true); receipt.put("mail_transport", "IN_MEMORY_ONLY");
        receipt.put("default_disabled_test_classpath_only", true); receipt.put("fit_calls", 0);
        receipt.put("holdout_scored", false); receipt.put("auto_containment", false); receipt.put("training_admitted", false);
        receipt.put("full_mailbox_compromise_distinguished", false);
        receipt.put("elapsed_seconds", Duration.between(started, Instant.now()).toMillis() / 1000.0);
        String checksum = publish(output, "capture.receipt.private.json", receipt);
        publish(output, "capture.commit.private.json", Map.of("receipt", "capture.receipt.private.json", "receipt_sha256", checksum));
    }

    private void installLocalMail() {
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var matcher = Pattern.compile("(?<!\\d)\\d{6}(?!\\d)").matcher(message.getText());
            if (!matcher.find()) throw new IllegalStateException("Local OTP delivery expected");
            excluded.add(message.getTo()[0]); excluded.add(matcher.group());
            lastDeliveredTo.set(message.getTo()[0]);
            delivered.put(message.getTo()[0], matcher.group()); return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    private void execute(Owned owned) throws Exception {
        Plan plan = owned.plan(); String ip = "127.0.0." + (plan.action().equals("EMAIL_CHANGE") ? 2 : 3);
        try (Client owner = new Client(ip); Client copied = new Client(ip)) {
            login(owner, owned);
            Client actor = owner;
            if (plan.capability().startsWith("COPIED_SESSION")) {
                for (var cookie : owner.cookies.getCookieStore().getCookies()) copied.cookies.getCookieStore().add(base(), cookie);
                actor = copied;
            }
            raw(actor, "GET", "/api/profile", null, null, 200);
            if (plan.action().equals("EMAIL_CHANGE")) post(actor, "/api/profile/email/otp", new ProfileEmailOtpRequest(owned.target()), null, 200);
            String proof = null;
            if (plan.proofMode().equals("VERIFIED")) {
                if (plan.caseId().equals("case-0")) protocolControls(owner, owned);
                proof = grant(owner, owned, false).proof();
            } else if (plan.proofMode().equals("INVALID") || plan.capability().equals("COPIED_SESSION_AND_NEW_MAILBOX_ONLY")) {
                String challenge = challenge(actor, owned);
                String actual = delivered.get(owned.anchor());
                post(actor, "/api/lab/action-proof/verify", new ActionProofLabConfiguration.Verification(challenge,
                        actual.equals("000000") ? "999999" : "000000"), null, 400);
                if (plan.proofMode().equals("INVALID")) { proof = "A".repeat(43); excluded.add(proof); }
            }
            if (plan.action().equals("EMAIL_CHANGE")) {
                post(actor, "/api/profile", new UpdateProfileRequest("Owned proof fixture", owned.target(),
                        "093" + String.format("%07d", Integer.parseInt(plan.caseId().substring(5))), delivered.get(owned.target())), proof, 200);
                assertThat(users.findById(owned.user().getId()).orElseThrow().getEmail().equals(owned.target())).isTrue();
            } else {
                post(actor, "/api/profile/password", new ChangePasswordRequest(owned.password(), owned.replacement(), owned.replacement()), proof, 204);
                assertThat(passwords.matches(owned.replacement(), users.findById(owned.user().getId()).orElseThrow().getPassword())).isTrue();
            }
            outcomes.add(Map.of("case_id", plan.caseId(), "ground_truth", plan.role().equals("OWNER")
                    ? "AUTHORIZED_OWNER_ACTION" : "CONTROLLED_UNAUTHORIZED_ACTION", "account_mutated", true,
                    "label_source", "SEALED_ROLE_MANIFEST", "http_status", plan.action().equals("EMAIL_CHANGE") ? 200 : 204));
            if (plan.caseId().equals("case-0")) afterEmailControls(owner, owned);
        }
    }

    private void protocolControls(Client client, Owned owned) throws Exception {
        Grant first = grant(client, owned, true);
        var context = binding(client, owned.user());
        List<ActionProofLabConfiguration.Context> invalid = List.of(
                new ActionProofLabConfiguration.Context("another-owned-account", context.authVersion(), context.session(), context.issuedAt()),
                new ActionProofLabConfiguration.Context(context.actor(), context.authVersion() + 1, context.session(), context.issuedAt()),
                new ActionProofLabConfiguration.Context(context.actor(), context.authVersion(), "f".repeat(64), context.issuedAt()));
        for (var mismatch : invalid) assertThat(proofs.consume(mismatch, owned.plan().action(), owned.target(), first.proof()).state()).isEqualTo("INVALID");
        assertThat(proofs.consume(context, "PASSWORD_CHANGE", owned.target(), first.proof()).state()).isEqualTo("INVALID");
        assertThat(proofs.consume(context, owned.plan().action(), "wrong-target@example.test", first.proof()).state()).isEqualTo("INVALID");
        controls.put("account_session_authversion_action_target_binding", true);
        long ttl = redis.getExpire(proofs.proofKey(first.proof()), TimeUnit.MILLISECONDS);
        assertThat(ttl).isPositive().isLessThanOrEqualTo(300_000);
        String stored = redis.opsForValue().get(proofs.proofKey(first.proof()));
        assertThat(stored.contains(first.proof()) || stored.contains(owned.target()) || stored.contains(owned.anchor())).isFalse();
        controls.put("opaque_receipt_hash_only_and_ttl_at_most_300_seconds", true);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var ready = new CountDownLatch(2); var start = new CountDownLatch(1);
            var futures = new ArrayList<java.util.concurrent.Future<String>>();
            for (int i = 0; i < 2; i++) futures.add(pool.submit(() -> {
                ready.countDown(); start.await();
                return proofs.consume(context, owned.plan().action(), owned.target(), first.proof()).state();
            }));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue(); start.countDown();
            var states = List.of(futures.get(0).get(5, TimeUnit.SECONDS), futures.get(1).get(5, TimeUnit.SECONDS));
            assertThat(states).containsExactlyInAnyOrder("VERIFIED", "INVALID");
        }
        assertThat(proofs.consume(context, owned.plan().action(), owned.target(), first.proof()).state()).isEqualTo("INVALID");
        controls.put("real_redis_concurrent_one_use_and_replay", true);
    }

    private void afterEmailControls(Client client, Owned owned) throws Exception {
        String latestMutableEmail = users.findById(owned.user().getId()).orElseThrow().getEmail();
        assertThat(latestMutableEmail.equals(owned.anchor())).isFalse();
        Grant fixed = grant(client, owned, false);
        assertThatThrownBy(() -> proofs.bindVerifiedFixture(owned.user().getId(), latestMutableEmail, "a".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        controls.put("mutable_profile_email_does_not_replace_fixed_anchor", true);
        // Correct channel proof does not establish human intent if that channel is also compromised.
        assertThat(proofs.consume(binding(client, owned.user()), owned.plan().action(), owned.target(), fixed.proof()).state()).isEqualTo("VERIFIED");
        controls.put("valid_proof_is_channel_control_not_actor_role", true);
        Grant expiring = grant(client, owned, false);
        redis.expire(proofs.proofKey(expiring.proof()), Duration.ofMillis(1)); Thread.sleep(20);
        assertThat(proofs.consume(binding(client, owned.user()), owned.plan().action(), owned.target(), expiring.proof()).state()).isEqualTo("INVALID");
        controls.put("expiry_control", "REAL_REDIS_TTL_SHORTENED_NO_EVENT_CLOCK_REWRITE");
        Grant versionBound = grant(client, owned, false);
        User updated = users.findById(owned.user().getId()).orElseThrow(); updated.setAuthVersion(1L); users.saveAndFlush(updated);
        raw(client, "GET", "/api/profile", null, null, 401); login(client, owned);
        assertThat(proofs.consume(binding(client, users.findById(owned.user().getId()).orElseThrow()), owned.plan().action(),
                owned.target(), versionBound.proof()).state()).isEqualTo("INVALID");
        controls.put("actual_authversion_change_invalidates_old_proof", true);
    }

    private Grant grant(Client client, Owned owned, boolean wrongFirst) throws Exception {
        String ref = challenge(client, owned), code = delivered.get(owned.anchor());
        if (wrongFirst) {
            post(client, "/api/lab/action-proof/verify", new ActionProofLabConfiguration.Verification(ref,
                    code.equals("000000") ? "999999" : "000000"), null, 400);
            controls.put("legitimate_wrong_code_retry_retains_owner_label", true);
        }
        String proof = json.readTree(post(client, "/api/lab/action-proof/verify",
                new ActionProofLabConfiguration.Verification(ref, code), null, 200).body()).path("proof").asText();
        assertThat(proof.length()).isEqualTo(43); excluded.add(proof);
        return new Grant(ref, proof);
    }
    private String challenge(Client client, Owned owned) throws Exception {
        String ref = json.readTree(post(client, "/api/lab/action-proof/challenge",
                new ActionProofLabConfiguration.Challenge(owned.plan().action(), owned.target()), null, 200).body()).path("challenge_ref").asText();
        assertThat(owned.anchor().equals(lastDeliveredTo.get())).isTrue();
        assertThat(ref.length()).isEqualTo(43); excluded.add(ref); return ref;
    }
    private ActionProofLabConfiguration.Context binding(Client client, User user) {
        String token = client.cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("access_token")).findFirst().orElseThrow().getValue();
        var metadata = jwt.extractSessionTelemetry(token, user.getId()).orElseThrow();
        return new ActionProofLabConfiguration.Context(user.getId(), user.getAuthVersion() == null ? 0 : user.getAuthVersion(),
                metadata.sessionPseudonym(), metadata.sessionIssuedAt().toString());
    }
    private Owned fixture(Plan plan) {
        String initial = "OwnedProofInitial#" + UUID.randomUUID(), replacement = "OwnedProofNew#" + UUID.randomUUID();
        var user = new User(); String id = "proof-" + UUID.randomUUID().toString().replace("-", "");
        user.setId(id); user.setUsername(id); user.setPassword(passwords.encode(initial)); user.setAuthVersion(0L);
        user.setRole("CUSTOMER"); user.setHoTen("Owned action proof fixture"); user.setEmail(id + "@example.test");
        user.setStatus("Hoat dong"); user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(user);
        String target = plan.action().equals("EMAIL_CHANGE") ? UUID.randomUUID() + "@example.test" : replacement;
        excluded.addAll(List.of(id, initial, replacement, target, user.getEmail()));
        return new Owned(plan, user, initial, replacement, target, user.getEmail());
    }
    private void login(Client client, Owned owned) throws Exception {
        post(client, "/api/auth/login", Map.of("username", owned.user().getUsername(), "password", owned.password()), null, 200);
        client.cookies.getCookieStore().getCookies().forEach(c -> excluded.add(c.getValue()));
    }
    private HttpResponse<String> post(Client client, String path, Object body, String proof, int status) throws Exception {
        client.csrf = json.readTree(raw(client, "GET", "/api/auth/csrf", null, null, 200).body()).path("token").asText();
        excluded.add(client.csrf); return raw(client, path.equals("/api/profile") || path.endsWith("/password") ? "PUT" : "POST", path, body, proof, status);
    }
    private HttpResponse<String> raw(Client client, String method, String path, Object body, String proof, int status) throws Exception {
        long delay = TimeUnit.MILLISECONDS.toNanos(210) - (System.nanoTime() - lastRequest);
        if (delay > 0) TimeUnit.NANOSECONDS.sleep(delay); lastRequest = System.nanoTime(); assertThat(++requests).isLessThanOrEqualTo(200);
        var builder = HttpRequest.newBuilder(base().resolve(path)).timeout(Duration.ofSeconds(5)).header("User-Agent", "OwnedActionProofFixture/1.0");
        if (body == null) builder.method(method, HttpRequest.BodyPublishers.noBody());
        else builder.header("Content-Type", "application/json").header("X-XSRF-TOKEN", client.csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        if (proof != null) builder.header(ActionProofLabConfiguration.HEADER, proof);
        var response = client.http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("%s %s", method, path).isEqualTo(status); return response;
    }
    private URI base() { return URI.create("http://127.0.0.1:" + port); }
    private String publish(Path output, String name, Object document) throws Exception {
        byte[] bytes = json.writeValueAsBytes(document); assertThat(bytes.length).isLessThan(512 * 1024);
        String text = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        for (String value : excluded) assertThat(text.contains(value)).as("Private value excluded from %s", name).isFalse();
        try (var file = FileChannel.open(output.resolve(name), Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            var buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) file.write(buffer); file.force(true);
        }
        try (var directory = FileChannel.open(output, StandardOpenOption.READ)) { directory.force(true); }
        return sha(bytes);
    }
    private static String sha(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static final class Client implements AutoCloseable {
        final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL); final HttpClient http; String csrf;
        Client(String address) throws Exception { http = HttpClient.newBuilder().cookieHandler(cookies).localAddress(InetAddress.getByName(address))
                .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build(); }
        @Override public void close() { http.close(); }
    }
}
