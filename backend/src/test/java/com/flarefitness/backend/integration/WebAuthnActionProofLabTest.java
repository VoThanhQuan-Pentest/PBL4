package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.exception.BadRequestException;
import com.upokecenter.cbor.CBORObject;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Synthetic JCA signer tests protocol handling; it is not evidence of a human-held authenticator. */
class WebAuthnActionProofLabTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static final String ACTION = "EMAIL_CHANGE", TARGET = "readiness-only@example.test";
    static final ActionProofLabConfiguration.Context ENROLL = new ActionProofLabConfiguration.Context("lab-fixture", 0, "session-enrollment", "2026-10-19T00:00:00Z");
    static final ActionProofLabConfiguration.Context SESSION = new ActionProofLabConfiguration.Context("lab-fixture", 0, "session-after-enrollment", "2026-10-19T00:00:01Z");

    @Test void newVerifierReusesCommittedPublicKeyWithFreshSessionAndChallengeOnly(@TempDir Path output) throws Exception {
        Fixture original = new Fixture(); String pin = archive(original, output);
        var oldOptions = original.lab.assertionOptions(SESSION, ACTION, TARGET);
        String oldResponse = original.auth.assertion(oldOptions, "localhost", "http://localhost:8123", null, true, false, 1);
        Fixture next = new Fixture(); next.lab.restoreVerifiedEnrollment(output, pin); next.now.addAndGet(1000);
        var fresh = new ActionProofLabConfiguration.Context(ENROLL.actor(), 0, "new-process-session",
                java.time.Instant.ofEpochMilli(next.now.get()).toString());
        assertThat(next.lab.browserStatus()).containsEntry("lifecycle_phase", "RESTORED_ASSERTION");
        assertThatThrownBy(() -> next.lab.registerOptions(fresh)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> next.lab.assertionOptions(SESSION, ACTION, TARGET)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> next.lab.assertionFinish(fresh, ACTION, TARGET, oldOptions.reference(), oldResponse))
                .isInstanceOf(BadRequestException.class);
        var options = next.lab.assertionOptions(fresh, ACTION, TARGET);
        assertThat(next.lab.assertionFinish(fresh, ACTION, TARGET, options.reference(),
                original.auth.assertion(options, "localhost", "http://localhost:8123", null, true, false, 2)).userVerified()).isTrue();
        assertThatThrownBy(() -> next.lab.assertionOptions(fresh, ACTION, TARGET)).isInstanceOf(BadRequestException.class);
        assertThat(next.lab.status()).containsEntry("registered_credentials", 1).containsEntry("successful_assertions", 1);
    }

    @Test void enrollmentOnlyPhaseCannotIssueOrAcceptAnAssertion(@TempDir Path output) throws Exception {
        Fixture f = new Fixture(); f.lab.enrollmentOnly(); archive(f, output);
        assertThat(f.lab.browserStatus()).containsEntry("lifecycle_phase", "ENROLL_ONLY");
        assertThatThrownBy(() -> f.lab.assertionOptions(SESSION, ACTION, TARGET)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, TARGET, "x".repeat(43), "{}"))
                .isInstanceOf(BadRequestException.class);
        assertThat(f.lab.status()).containsEntry("successful_assertions", 0);
    }

    @Test void wrongPinPartialCommitAndTamperingKeepRestoreEnrollmentClosed(@TempDir Path output) throws Exception {
        Fixture source = new Fixture(); String pin = archive(source, output);
        Fixture wrongPin = new Fixture();
        assertThatThrownBy(() -> wrongPin.lab.restoreVerifiedEnrollment(output, "0".repeat(64))).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> wrongPin.lab.registerOptions(SESSION)).isInstanceOf(BadRequestException.class);
        Path marker = output.resolve("verified-enrollment.commit.private.json"); byte[] bytes = Files.readAllBytes(marker);
        Files.delete(marker);
        assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(output, pin)).isInstanceOf(BadRequestException.class);
        Files.write(marker, bytes, StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(marker, PosixFilePermissions.fromString("rw-------"));
        Files.writeString(output.resolve("verified-enrollment.receipt.private.json"), "{}");
        assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(output, pin)).isInstanceOf(BadRequestException.class);
    }

    @Test void pinnedButWrongScopeOrUnverifiedMetadataCannotBeImported(@TempDir Path output) throws Exception {
        Fixture source = new Fixture(); Path original = Files.createDirectory(output.resolve("original")); archive(source, original);
        ObjectNode valid = (ObjectNode) JSON.readTree(Files.readAllBytes(original.resolve("verified-enrollment.receipt.private.json")));
        var variants = new ArrayList<ObjectNode>();
        variants.add(valid.deepCopy().put("lab_actor", "another-actor"));
        variants.add(valid.deepCopy().put("origin", "http://localhost:9999"));
        variants.add(valid.deepCopy().put("rp_id", "evil.example"));
        variants.add(valid.deepCopy().put("schema_version", 2));
        variants.add(valid.deepCopy().put("user_verified", false));
        variants.add(valid.deepCopy().put("human_identity_proven", true));
        variants.add(valid.deepCopy().put("hardware_attestation_trusted", true));
        variants.add(valid.deepCopy().put("signature_count_at_registration", -1));
        variants.add(valid.deepCopy().put("verified_at_epoch_ms", source.now.get() + 1000));
        variants.add(valid.deepCopy().put("public_key_cose_b64url", "AA"));
        variants.add(valid.deepCopy().put("backed_up", true).put("backup_eligible", false));
        variants.add(valid.deepCopy().put("unexpected_session", ENROLL.session()));
        for (int i = 0; i < variants.size(); i++) {
            Path dir = Files.createDirectory(output.resolve("bad-" + i));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            String hash = WebAuthnLabArtifacts.publish(dir, JSON, "verified-enrollment.receipt.private.json", variants.get(i));
            String pin = WebAuthnLabArtifacts.publish(dir, JSON, "verified-enrollment.commit.private.json",
                    Map.of("receipt", "verified-enrollment.receipt.private.json", "receipt_sha256", hash));
            assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(dir, pin)).isInstanceOf(BadRequestException.class);
        }
    }

    @Test void restoreRefusesSharedFilesAndSymlinkOrHardlinkMarkers(@TempDir Path output) throws Exception {
        Fixture source = new Fixture(); String pin = archive(source, output);
        Path marker = output.resolve("verified-enrollment.commit.private.json");
        Files.setPosixFilePermissions(marker, PosixFilePermissions.fromString("rw-r-----"));
        assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(output, pin)).isInstanceOf(BadRequestException.class);
        Files.setPosixFilePermissions(marker, PosixFilePermissions.fromString("rw-------"));
        Path extra = output.resolve("extra.private.json"); Files.createLink(extra, marker);
        assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(output, pin)).isInstanceOf(BadRequestException.class);
        Files.delete(extra); Files.move(marker, extra); Files.createSymbolicLink(marker, extra);
        assertThatThrownBy(() -> new Fixture().lab.restoreVerifiedEnrollment(output, pin)).isInstanceOf(BadRequestException.class);
    }

    private static String archive(Fixture source, Path output) throws Exception {
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        source.lab.recordVerifiedEnrollmentWith(record -> {
            String hash = WebAuthnLabArtifacts.publish(output, JSON, "verified-enrollment.receipt.private.json", record);
            WebAuthnLabArtifacts.publish(output, JSON, "verified-enrollment.commit.private.json",
                    Map.of("receipt", "verified-enrollment.receipt.private.json", "receipt_sha256", hash));
        });
        source.enroll();
        return WebAuthnLabArtifacts.sha256(Files.readAllBytes(output.resolve("verified-enrollment.commit.private.json")));
    }

    @Test void verifiedPublicEnrollmentIsCommittedBeforeReturningWithoutPrivateOrSessionSecrets(@TempDir Path output) throws Exception {
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        Fixture recorded = new Fixture();
        recorded.lab.recordVerifiedEnrollmentWith(record -> {
            String hash = WebAuthnLabArtifacts.publish(output, JSON, "verified-enrollment.receipt.private.json", record);
            WebAuthnLabArtifacts.publish(output, JSON, "verified-enrollment.commit.private.json",
                    Map.of("receipt", "verified-enrollment.receipt.private.json", "receipt_sha256", hash));
        });
        var options = recorded.lab.registerOptions(ENROLL);
        // A recorder cannot be changed after the enrollment slot has been granted.
        assertThatThrownBy(() -> recorded.lab.recordVerifiedEnrollmentWith(ignored -> { })).isInstanceOf(IllegalStateException.class);
        recorded.lab.registerFinish(ENROLL, options.reference(), recorded.auth.registration(options));
        byte[] stored = Files.readAllBytes(output.resolve("verified-enrollment.receipt.private.json"));
        var publicRecord = new ObjectMapper().readTree(stored);
        var marker = new ObjectMapper().readTree(Files.readAllBytes(output.resolve("verified-enrollment.commit.private.json")));
        assertThat(marker.path("receipt_sha256").asText()).isEqualTo(WebAuthnLabArtifacts.sha256(stored));
        assertThat(publicRecord.path("origin").asText()).isEqualTo("http://localhost:8123");
        assertThat(publicRecord.path("lab_actor").asText()).isEqualTo(ENROLL.actor());
        assertThat(publicRecord.path("user_verified").asBoolean()).isTrue();
        assertThat(publicRecord.path("hardware_attestation_trusted").asBoolean()).isFalse();
        assertThat(publicRecord.path("public_key_cose_b64url").asText()).isNotBlank();
        String text = new String(stored, StandardCharsets.UTF_8);
        assertThat(text).doesNotContain(ENROLL.session(), options.reference(), "credential_json", "targetKey",
                Base64.getUrlEncoder().withoutPadding().encodeToString(recorded.auth.key.getPrivate().getEncoded()));
        assertThat(Files.getPosixFilePermissions(output.resolve("verified-enrollment.receipt.private.json")))
                .isEqualTo(PosixFilePermissions.fromString("rw-------"));
    }

    @Test void invalidEnrollmentCannotPublishAndInterruptedPublicationDoesNotReopenCreation(@TempDir Path output) throws Exception {
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        Fixture f = new Fixture(); var calls = new java.util.concurrent.atomic.AtomicInteger();
        f.lab.recordVerifiedEnrollmentWith(record -> {
            calls.incrementAndGet();
            WebAuthnLabArtifacts.publish(output, JSON, "verified-enrollment.receipt.private.json", record);
            throw new java.io.IOException("Synthetic interruption before commit marker");
        });
        var options = f.lab.registerOptions(ENROLL);
        assertThatThrownBy(() -> f.lab.registerFinish(ENROLL, options.reference(), "invalid-json")).isInstanceOf(BadRequestException.class);
        assertThat(calls.get()).isZero();
        String response = f.auth.registration(options);
        assertThatThrownBy(() -> f.lab.registerFinish(ENROLL, options.reference(), response)).isInstanceOf(BadRequestException.class);
        assertThat(calls.get()).isEqualTo(1);
        assertThat(output.resolve("verified-enrollment.receipt.private.json")).exists();
        assertThat(output.resolve("verified-enrollment.commit.private.json")).doesNotExist();
        assertThatThrownBy(() -> f.lab.registerOptions(ENROLL)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> f.lab.registerFinish(ENROLL, options.reference(), response)).isInstanceOf(BadRequestException.class);
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test void artifactPublicationRefusesOverwriteSymlinksAndSharedDirectories(@TempDir Path output) throws Exception {
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        WebAuthnLabArtifacts.publish(output, JSON, "record.private.json", Map.of("public", true));
        assertThatThrownBy(() -> WebAuthnLabArtifacts.publish(output, JSON, "record.private.json", Map.of("public", false)))
                .isInstanceOf(FileAlreadyExistsException.class);
        Files.createSymbolicLink(output.resolve("symlink.private.json"), output.resolve("record.private.json"));
        assertThatThrownBy(() -> WebAuthnLabArtifacts.publish(output, JSON, "symlink.private.json", Map.of()))
                .isInstanceOf(FileAlreadyExistsException.class);
        assertThatThrownBy(() -> WebAuthnLabArtifacts.publish(output, JSON, "../outside.private.json", Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThatThrownBy(() -> WebAuthnLabArtifacts.publish(output, JSON, "shared.private.json", Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(output.resolve("shared.private.json")).doesNotExist();
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
    }

    @Test void fixedHandoffPortIsValidatedAndPageWaitsForFixtureBootstrap() throws Exception {
        assertThat(WebAuthnLabConfiguration.requestedPort(null)).isZero();
        assertThat(WebAuthnLabConfiguration.requestedPort("39137")).isEqualTo(39137);
        for (String invalid : List.of("0", "80", "-1", "65536", "not-a-port"))
            assertThatThrownBy(() -> WebAuthnLabConfiguration.requestedPort(invalid)).isInstanceOf(IllegalArgumentException.class);
        var lab = new WebAuthnActionProofLab(org.mockito.Mockito.mock(WebAuthnActionProofLab.Store.class), JSON, System::currentTimeMillis);
        assertThat(lab.browserStatus()).containsEntry("remaining_ms", 0L);
        var page = new WebAuthnLabConfiguration.Page(lab);
        var request = new org.springframework.mock.web.MockHttpServletRequest(); request.setRemoteAddr("127.0.0.1");
        assertThat(page.page(request)).contains("http-equiv=refresh").doesNotContain("Đăng ký 1 khóa thử nghiệm");
        lab.configure(ENROLL.actor(), "http://localhost:39137", System.currentTimeMillis() + 60_000);
        assertThat((Long) lab.browserStatus().get("remaining_ms")).isPositive().isLessThanOrEqualTo(60_000L);
        assertThat(page.page(request)).contains("Đăng ký 1 khóa thử nghiệm");
    }

    @Test void browserSerializerTransportsAttachmentAndExtensionFieldsAreAccepted() throws Exception {
        Fixture f = new Fixture(); var options = f.lab.registerOptions(ENROLL);
        ObjectNode browser = (ObjectNode) JSON.readTree(f.auth.registration(options));
        browser.put("authenticatorAttachment", "cross-platform");
        ((ObjectNode) browser.get("response")).set("transports", JSON.valueToTree(List.of("usb", "nfc", "hybrid")));
        ((ObjectNode) browser.get("clientExtensionResults")).set("credProps", JSON.valueToTree(Map.of("rk", false)));
        var body = JSON.treeToValue(JSON.createObjectNode().put("reference", options.reference())
                .put("credential_json", JSON.writeValueAsString(browser)), WebAuthnLabConfiguration.Finish.class);
        assertThat(body.credentialJson()).isNotBlank();
        f.lab.registerFinish(ENROLL, body.reference(), body.credentialJson());
        assertThat(f.lab.status()).containsEntry("registered_credentials", 1);
    }

    @Test void realSignatureAndAllScopeBindingsAreRequiredAndReceiptIsOneUse() throws Exception {
        Fixture f = new Fixture(); f.enroll();
        var o = f.lab.assertionOptions(SESSION, ACTION, TARGET); String response = f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, false, 1);
        for (var context : List.of(new ActionProofLabConfiguration.Context("another-account", 0, SESSION.session(), SESSION.issuedAt()),
                new ActionProofLabConfiguration.Context(SESSION.actor(), 1, SESSION.session(), SESSION.issuedAt()),
                new ActionProofLabConfiguration.Context(SESSION.actor(), 0, "another-session", SESSION.issuedAt()))) {
            assertThatThrownBy(() -> f.lab.assertionFinish(context, ACTION, TARGET, o.reference(), response)).isInstanceOf(BadRequestException.class);
        }
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, "PASSWORD_CHANGE", TARGET, o.reference(), response)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, "different@example.test", o.reference(), response)).isInstanceOf(BadRequestException.class);
        var verified = f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), response);
        assertThat(verified.userVerified()).isTrue(); assertThat(verified.evidence().scopeBound()).isTrue();
        assertThat(verified.evidence().state()).isEqualTo("VERIFIED");
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), response)).isInstanceOf(BadRequestException.class);
    }

    @Test void originRpChallengeSignatureAndUserVerificationCannotBeForged() throws Exception {
        Fixture f = new Fixture(); f.enroll(); var o = f.lab.assertionOptions(SESSION, ACTION, TARGET);
        List<String> bad = List.of(
                f.auth.assertion(o, "localhost", "https://evil.example", null, true, false, 1),
                f.auth.assertion(o, "evil.example", "http://localhost:8123", null, true, false, 1),
                f.auth.assertion(o, "localhost", "http://localhost:8123", "wrong-challenge", true, false, 1),
                f.auth.assertion(o, "localhost", "http://localhost:8123", null, false, false, 1),
                f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, true, 1));
        for (String response : bad) assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), response)).isInstanceOf(BadRequestException.class);
        assertThat(f.lab.status().get("successful_assertions")).isEqualTo(0);
        assertThat(f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(),
                f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, false, 1)).evidence().state()).isEqualTo("VERIFIED");
    }

    @Test void expiredCeremonyAndMalformedResponseNeverProduceProof() throws Exception {
        Fixture f = new Fixture(); f.enroll(); var o = f.lab.assertionOptions(SESSION, ACTION, TARGET);
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), "x".repeat(65_537))).isInstanceOf(BadRequestException.class);
        String response = f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, false, 1);
        f.now.addAndGet(300_001);
        assertThatThrownBy(() -> f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), response)).isInstanceOf(BadRequestException.class);
        assertThat(f.lab.status().get("successful_assertions")).isEqualTo(0);
        f.now.addAndGet(300_000);
        assertThat(f.lab.browserStatus()).containsEntry("remaining_ms", 0L);
    }

    @Test void concurrentSignedReplayHasExactlyOneWinner() throws Exception {
        Fixture f = new Fixture(); f.enroll(); var o = f.lab.assertionOptions(SESSION, ACTION, TARGET);
        String response = f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, false, 0);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var start = new CountDownLatch(1); var results = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < 2; i++) results.add(pool.submit(() -> {
                start.await();
                try { f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), response); return true; }
                catch (BadRequestException invalid) { return false; }
            }));
            start.countDown(); int wins = 0;
            for (var result : results) if (result.get(5, TimeUnit.SECONDS)) wins++;
            assertThat(wins).isEqualTo(1);
        }
    }

    @Test void enrollmentClosesAndFreshSessionAndTwoAssertionCapAreEnforced() throws Exception {
        Fixture f = new Fixture(); var enrollment = f.lab.registerOptions(ENROLL);
        assertThatThrownBy(() -> f.lab.registerOptions(ENROLL)).isInstanceOf(BadRequestException.class);
        f.lab.registerFinish(ENROLL, enrollment.reference(), f.auth.registration(enrollment));
        assertThatThrownBy(() -> f.lab.registerOptions(ENROLL)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> f.lab.assertionOptions(ENROLL, ACTION, TARGET)).isInstanceOf(BadRequestException.class);
        for (int count = 1; count <= 2; count++) {
            var o = f.lab.assertionOptions(SESSION, ACTION, TARGET);
            f.lab.assertionFinish(SESSION, ACTION, TARGET, o.reference(), f.auth.assertion(o, "localhost", "http://localhost:8123", null, true, false, count));
        }
        assertThatThrownBy(() -> f.lab.assertionOptions(SESSION, ACTION, TARGET)).isInstanceOf(BadRequestException.class);
        assertThat(f.lab.status()).containsEntry("registered_credentials", 1).containsEntry("successful_assertions", 2)
                .containsEntry("human_identity_proven", false).containsEntry("hardware_attestation_trusted", false);
    }

    static final class Fixture {
        final AtomicLong now = new AtomicLong(1_800_000_000_000L);
        final ConcurrentMap<String, String> pending = new ConcurrentHashMap<>();
        final WebAuthnActionProofLab lab = new WebAuthnActionProofLab(new WebAuthnActionProofLab.Store() {
            public void put(String key, String value, long deadline) { assertThat(pending.putIfAbsent(key, value)).isNull(); }
            public String get(String key) { return pending.get(key); }
            public boolean take(String key, String value, long deadline) { return now.get() < deadline && pending.remove(key, value); }
        }, JSON, now::get);
        final SyntheticAuthenticator auth;
        Fixture() throws Exception { auth = new SyntheticAuthenticator(); lab.configure(ENROLL.actor(), "http://localhost:8123", now.get() + 600_000); }
        void enroll() throws Exception { var options = lab.registerOptions(ENROLL); lab.registerFinish(ENROLL, options.reference(), auth.registration(options)); }
    }

    static final class SyntheticAuthenticator {
        final KeyPair key;
        final byte[] credentialId = new byte[32];
        byte[] handle;
        SyntheticAuthenticator() throws Exception {
            var generator = KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp256r1"));
            key = generator.generateKeyPair(); new SecureRandom().nextBytes(credentialId);
        }
        String registration(WebAuthnActionProofLab.Options options) throws Exception {
            var data = JSON.readTree(options.publicKeyJson()).path("publicKey"); handle = Base64.getUrlDecoder().decode(data.path("user").path("id").asText());
            var publicKey = (ECPublicKey) key.getPublic();
            var cose = CBORObject.NewMap().Add(1, 2).Add(3, -7).Add(-1, 1)
                    .Add(-2, coordinate(publicKey.getW().getAffineX().toByteArray())).Add(-3, coordinate(publicKey.getW().getAffineY().toByteArray()));
            var auth = new ByteArrayOutputStream(); auth.write(authData("localhost", 0x45, 0)); auth.write(new byte[16]);
            auth.write(ByteBuffer.allocate(2).putShort((short) credentialId.length).array()); auth.write(credentialId); auth.write(cose.EncodeToBytes());
            byte[] attestation = CBORObject.NewMap().Add("fmt", "none").Add("attStmt", CBORObject.NewMap())
                    .Add("authData", auth.toByteArray()).EncodeToBytes();
            ObjectNode response = JSON.createObjectNode().put("clientDataJSON", b64(clientData("webauthn.create", data.path("challenge").asText(), "http://localhost:8123")))
                    .put("attestationObject", b64(attestation));
            return envelope(response);
        }
        String assertion(WebAuthnActionProofLab.Options options, String rp, String origin, String challengeOverride, boolean uv, boolean corrupt, int count) throws Exception {
            String challenge = challengeOverride == null ? JSON.readTree(options.publicKeyJson()).path("publicKey").path("challenge").asText() : challengeOverride;
            byte[] client = clientData("webauthn.get", challenge, origin), auth = authData(rp, uv ? 5 : 1, count);
            Signature signer = Signature.getInstance("SHA256withECDSA"); signer.initSign(key.getPrivate()); signer.update(auth); signer.update(MessageDigest.getInstance("SHA-256").digest(client));
            byte[] signature = signer.sign(); if (corrupt) signature[signature.length - 1] ^= 1;
            return envelope(JSON.createObjectNode().put("clientDataJSON", b64(client)).put("authenticatorData", b64(auth))
                    .put("signature", b64(signature)).put("userHandle", b64(handle)));
        }
        private String envelope(ObjectNode response) throws Exception {
            ObjectNode root = JSON.createObjectNode().put("id", b64(credentialId)).put("rawId", b64(credentialId)).put("type", "public-key");
            root.set("response", response); root.set("clientExtensionResults", JSON.createObjectNode()); return JSON.writeValueAsString(root);
        }
        private static byte[] clientData(String type, String challenge, String origin) throws Exception {
            return JSON.writeValueAsBytes(Map.of("type", type, "challenge", challenge, "origin", origin, "crossOrigin", false));
        }
        private static byte[] authData(String rp, int flags, int count) throws Exception {
            return ByteBuffer.allocate(37).put(MessageDigest.getInstance("SHA-256").digest(rp.getBytes(StandardCharsets.UTF_8))).put((byte) flags).putInt(count).array();
        }
        private static byte[] coordinate(byte[] bytes) { byte[] out = new byte[32]; System.arraycopy(bytes, Math.max(0, bytes.length - 32), out, Math.max(0, 32 - bytes.length), Math.min(32, bytes.length)); return out; }
        private static String b64(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    }
}
