package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.service.ProfileService;
import com.flarefitness.backend.service.siem.SecurityEventExportWorker;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@EnabledIfSystemProperty(named = "postlogin.webauthn.device.enabled", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false",
        "siem.prevention.enabled=false", "siem.prevention.demo-enabled=false",
        "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
        "siem.security-events.webauthn-lab-enabled=true", "app.security.trusted-proxy-cidrs=",
        "logging.level.AUDIT=OFF", "management.health.mail.enabled=false"
})
@Import(WebAuthnLabConfiguration.class)
class WebAuthnDeviceReadinessIntegrationTest extends ContainerizedIntegrationTest {
    @DynamicPropertySource static void fixedPortForEarlyHandoff(DynamicPropertyRegistry registry) {
        String requested = System.getProperty("postlogin.webauthn.device.port");
        if (requested != null) registry.add("server.port", () -> WebAuthnLabConfiguration.requestedPort(requested));
    }
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired WebAuthnActionProofLab lab;
    @Autowired CountDownLatch completed;
    @Autowired StringRedisTemplate redis;
    @Autowired SiemSecurityEventRepository events;
    @Autowired SiemUebaModelJobRepository jobs;
    @MockitoBean JavaMailSender mail;
    @MockitoBean SecurityEventExportWorker rawOutbox;
    @MockitoSpyBean ProfileService profiles;

    @Test @Timeout(550)
    void observesAtMostOneRealCredentialWithoutExecutingSensitiveActions() throws Exception {
        String requested = System.getProperty("postlogin.webauthn.device.port");
        if (requested != null) assertThat(port).isEqualTo(WebAuthnLabConfiguration.requestedPort(requested));
        Path repo = Path.of("").toAbsolutePath().normalize();
        if (!Files.isRegularFile(repo.resolve("backend/pom.xml"))) repo = repo.getParent();
        Path output = SensitiveActionControlledCaptureArtifacts.createFreshPrivateDirectory(repo,
                System.getProperty("postlogin.webauthn.device.output"));
        int seconds = Math.min(500, Integer.getInteger("postlogin.webauthn.device.wait-seconds", 300));
        String lifecycle = System.getProperty("postlogin.webauthn.device.lifecycle", "readiness");
        assertThat(lifecycle).isIn("readiness", "enroll", "restore");
        Path enrollmentDirectory = output;
        String restoreHash = null;
        User user = new User(); user.setId("webauthn-lab-owner"); user.setUsername(WebAuthnLabConfiguration.USERNAME);
        user.setPassword(passwords.encode(WebAuthnLabConfiguration.PASSWORD)); user.setAuthVersion(0L); user.setRole("CUSTOMER");
        user.setHoTen("Disposable WebAuthn lab owner"); user.setEmail("webauthn-owner@example.test");
        user.setStatus("Hoat dong"); user.setDeleted(false); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(user); String initialPasswordHash = user.getPassword(); long jobsBefore = jobs.count();
        lab.recordVerifiedEnrollmentWith(record -> {
            String hash = publish(output, "verified-enrollment.receipt.private.json", record);
            publish(output, "verified-enrollment.commit.private.json", Map.of("receipt", "verified-enrollment.receipt.private.json",
                    "receipt_sha256", hash));
        });
        String origin = "http://localhost:" + port;
        if (lifecycle.equals("enroll")) lab.enrollmentOnly();
        // End ceremonies conservatively before the bounded device wait can finish.
        lab.configure(user.getId(), origin, System.currentTimeMillis() + seconds * 1000L);
        if (lifecycle.equals("restore")) {
            enrollmentDirectory = Path.of(System.getProperty("postlogin.webauthn.device.restore-input")).toAbsolutePath().normalize();
            assertThat(enrollmentDirectory.getParent()).isEqualTo(repo.resolve("observability/runtime"));
            restoreHash = System.getProperty("postlogin.webauthn.device.restore-commit-sha256");
            lab.restoreVerifiedEnrollment(enrollmentDirectory, restoreHash);
            long readyLimit = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(1500);
            while (!lab.configured() && System.nanoTime() < readyLimit) Thread.sleep(20);
            assertThat(lab.configured()).isTrue();
        }
        var controls = redisAndHttpControls(origin);
        String readyHash = publish(output, "device-ready.private.json", Map.of("status", "WAITING_FOR_REAL_DEVICE",
                "url", origin + "/lab/webauthn", "wait_seconds", seconds, "maximum_credentials", 1,
                "maximum_sensitive_attempts", 0, "maximum_new_fits", 0, "server_process_id", ProcessHandle.current().pid(),
                "lifecycle_phase", lifecycle, "maximum_additional_credentials", lifecycle.equals("restore") ? 0 : 1));
        boolean finished = completed.await(seconds, TimeUnit.SECONDS);
        var status = lab.status();
        assertThat(((Number) status.get("registered_credentials")).intValue()).isBetween(0, 1);
        assertThat(((Number) status.get("successful_assertions")).intValue()).isBetween(0, 2);
        User after = users.findById(user.getId()).orElseThrow();
        assertThat(after.getPassword()).isEqualTo(initialPasswordHash); assertThat(after.getEmail()).isEqualTo("webauthn-owner@example.test");
        assertThat(jobs.count()).isEqualTo(jobsBefore);
        verify(profiles, never()).updateProfile(anyString(), any());
        verify(profiles, never()).changePassword(anyString(), any());
        verifyNoInteractions(mail);
        var source = events.findAccountEvidence(user.getId(), LocalDateTime.now(ZoneOffset.UTC).minusMinutes(15),
                LocalDateTime.now(ZoneOffset.UTC).plusSeconds(1), PageRequest.of(0, 200)).getContent();
        assertThat(source.stream().noneMatch(e -> Set.of("SENSITIVE_ACTION_ATTEMPT", "DOMAIN_ACTION").contains(e.getEventType()))).isTrue();
        boolean observed = finished && ((Number) status.get("successful_assertions")).intValue() > 0;
        String outcome = !observed ? "INCONCLUSIVE_REAL_DEVICE_NOT_OBSERVED" : Boolean.TRUE.equals(status.get("backup_eligible"))
                ? "INCONCLUSIVE_DEVICE_OR_INDEPENDENCE" : "READY_PROTOCOL_DEVICE_OBSERVED_ONLY";
        if (lifecycle.equals("enroll") && finished && ((Number) status.get("registered_credentials")).intValue() == 1)
            outcome = "ENROLLMENT_COMMITTED_AWAITING_RESTART";
        if (lifecycle.equals("restore") && observed) outcome = "PUBLIC_ENROLLMENT_REUSED_NEW_PROCESS_ASSERTION_VERIFIED";
        var receipt = new LinkedHashMap<String, Object>();
        receipt.put("status", outcome); receipt.put("browser_assertion_observed", observed); receipt.put("protocol_status", status);
        receipt.put("lifecycle_phase", lifecycle);
        receipt.put("server_process_id", ProcessHandle.current().pid());
        receipt.put("public_enrollment_recovery_proven", lifecycle.equals("restore") && observed);
        if (restoreHash != null) receipt.put("supervisor_pinned_enrollment_commit_sha256", restoreHash);
        receipt.put("physical_device_independence_verified", false);
        receipt.put("device_provenance", "MANUAL_BROWSER_FLOW_WITHOUT_TRUSTED_HARDWARE_ATTESTATION");
        receipt.put("operator_device_independence_reported", true); receipt.put("hardware_attestation_trusted", false);
        receipt.put("human_identity_or_intent_proven", false); receipt.put("virtual_authenticator_used_for_device_evidence", false);
        receipt.put("controls", controls); receipt.put("ready_file_sha256", readyHash);
        receipt.put("account_email_and_password_unchanged", true); receipt.put("sensitive_attempts", 0);
        receipt.put("fit_calls", 0); receipt.put("training_admitted", false); receipt.put("holdout_scored", false);
        receipt.put("auto_containment", false); receipt.put("aws_changed", false);
        if (((Number) status.get("registered_credentials")).intValue() == 1) {
            var enrollment = json.readTree(Files.readString(enrollmentDirectory.resolve("verified-enrollment.commit.private.json")));
            String expected = enrollment.path("receipt_sha256").asText();
            assertThat(enrollment.path("receipt").asText()).isEqualTo("verified-enrollment.receipt.private.json");
            assertThat(WebAuthnLabArtifacts.sha256(Files.readAllBytes(enrollmentDirectory.resolve("verified-enrollment.receipt.private.json"))))
                    .isEqualTo(expected);
            if (restoreHash != null) {
                String markerHash = WebAuthnLabArtifacts.sha256(Files.readAllBytes(
                        enrollmentDirectory.resolve("verified-enrollment.commit.private.json")));
                assertThat(markerHash).isEqualTo(restoreHash);
            }
            receipt.put("verified_public_credential_record", Map.of("directory", enrollmentDirectory.toString(),
                    "receipt", "verified-enrollment.receipt.private.json", "receipt_sha256", expected,
                    "authentication_import_enabled", lifecycle.equals("restore")));
        }
        String hash = publish(output, "device.receipt.private.json", receipt);
        publish(output, "device.commit.private.json", Map.of("receipt", "device.receipt.private.json", "receipt_sha256", hash));
    }

    private Map<String, Object> redisAndHttpControls(String origin) throws Exception {
        var store = new WebAuthnLabConfiguration.RedisStore(redis);
        String key = "lab:ueba:webauthn:control:" + UUID.randomUUID(); long deadline = System.currentTimeMillis() + 300_000;
        store.put(key, "non-secret-control", deadline);
        assertThat(redis.getExpire(key, TimeUnit.MILLISECONDS)).isPositive().isLessThanOrEqualTo(300_000);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var start = new CountDownLatch(1); var first = pool.submit(() -> { start.await(); return store.take(key, "non-secret-control", deadline); });
            var second = pool.submit(() -> { start.await(); return store.take(key, "non-secret-control", deadline); });
            start.countDown(); assertThat(List.of(first.get(3, TimeUnit.SECONDS), second.get(3, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
        }
        assertThat(store.take(key, "non-secret-control", deadline)).isFalse();
        store.put(key, "non-secret-control", deadline); redis.expire(key, Duration.ofMillis(1)); Thread.sleep(20);
        assertThat(store.take(key, "non-secret-control", deadline)).isFalse();
        var cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        try (var http = HttpClient.newBuilder().cookieHandler(cookies).connectTimeout(Duration.ofSeconds(5)).build()) {
            var page = http.send(HttpRequest.newBuilder(URI.create(origin + "/lab/webauthn")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertThat(page.statusCode()).isEqualTo(200); assertThat(page.body()).contains("Đăng ký 1 khóa thử nghiệm");
            String endpoint = origin + "/api/lab/action-proof/webauthn/register/options";
            var missing = http.send(HttpRequest.newBuilder(URI.create(endpoint)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(missing.statusCode()).isEqualTo(403);
            var csrf = http.send(HttpRequest.newBuilder(URI.create(origin + "/api/auth/csrf")).GET().build(), HttpResponse.BodyHandlers.ofString());
            String token = json.readTree(csrf.body()).path("token").asText();
            var anonymous = http.send(HttpRequest.newBuilder(URI.create(endpoint)).header("Content-Type", "application/json").header("X-XSRF-TOKEN", token)
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(anonymous.statusCode()).isEqualTo(401);
        }
        return Map.of("real_redis_one_use_concurrent_and_replay", true, "real_redis_shortened_ttl_expiry", true,
                "maximum_300_second_ttl", true, "ordinary_auth_and_csrf_required_for_ceremonies", true,
                "public_page_only_read_only", true);
    }

    private String publish(Path output, String name, Object value) throws Exception {
        return WebAuthnLabArtifacts.publish(output, json, name, value);
    }
}
