package com.flarefitness.backend.integration;

import static com.flarefitness.backend.integration.ActionProofLabConfiguration.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.flarefitness.backend.exception.BadRequestException;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.LongSupplier;
import java.nio.file.Path;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Test-only alternative proof ceremony. No login grant or business-operation execution. */
final class WebAuthnActionProofLab {
    interface Store {
        void put(String key, String value, long expiresAt);
        String get(String key);
        boolean take(String key, String value, long expiresAt);
    }
    @FunctionalInterface interface EnrollmentRecorder {
        void record(Map<String, Object> publicRecord) throws Exception;
    }
    record Pending(Ticket scope, String kind, String requestJson) { }
    record Options(String reference, @JsonProperty("public_key_json") String publicKeyJson) { }
    record Verified(Evidence evidence, @JsonProperty("user_verified") boolean userVerified,
                    @JsonProperty("backup_eligible") boolean backupEligible, @JsonProperty("backed_up") boolean backedUp) { }
    private final Store store;
    private final ObjectMapper json;
    private final LongSupplier clock;
    private final SecureRandom random = new SecureRandom();
    private final byte[] targetKey = new byte[32];
    private final Repository credentials = new Repository();
    private RelyingParty rp;
    private Context enrolledContext;
    private String fixedOrigin;
    private EnrollmentRecorder enrollmentRecorder = ignored -> { };
    private boolean recorderAttached;
    private boolean enrollmentOnly;
    private boolean restored;
    private long restoredSessionFloor;
    private long deadline;
    private int requests;
    private int assertions;
    private boolean backupEligible;
    private boolean backedUp;
    private boolean registrationStarted;

    WebAuthnActionProofLab(Store store, ObjectMapper json, LongSupplier clock) {
        this.store = store; this.json = json; this.clock = clock; random.nextBytes(targetKey);
    }

    /** Trusted harness bootstrap only. No HTTP route can install a recorder or read this record. */
    synchronized void recordVerifiedEnrollmentWith(EnrollmentRecorder recorder) {
        if (registrationStarted || recorderAttached) throw new IllegalStateException("Enrollment recorder already fixed");
        enrollmentRecorder = Objects.requireNonNull(recorder);
        recorderAttached = true;
    }

    synchronized void enrollmentOnly() {
        if (registrationStarted) throw new IllegalStateException("Enrollment already started");
        enrollmentOnly = true;
    }

    /** Trusted test bootstrap only; a failed restore also permanently closes enrollment. */
    synchronized void restoreVerifiedEnrollment(Path directory, String expectedCommitHash) {
        if (rp == null || registrationStarted || enrollmentOnly) throw invalid();
        registrationStarted = true;
        try {
            var saved = WebAuthnLabArtifacts.readVerified(directory, json, expectedCommitHash, credentials.actor, fixedOrigin, clock.getAsLong());
            credentials.credential = saved.credential(); credentials.handle = saved.credential().getUserHandle();
            backupEligible = saved.backupEligible(); backedUp = saved.backedUp();
            restoredSessionFloor = Math.floorDiv(clock.getAsLong(), 1000) + 1;
            restored = true;
        } catch (Exception failure) { throw invalid(); }
    }

    synchronized void configure(String actor, String origin, long expiresAt) {
        if (rp != null || actor == null || !origin.matches("http://localhost:[0-9]{1,5}")
                || expiresAt <= clock.getAsLong() || expiresAt - clock.getAsLong() > 600_000) {
            throw new IllegalArgumentException("Fixed loopback lab configuration required");
        }
        credentials.actor = actor; credentials.handle = new ByteArray(randomBytes()); deadline = expiresAt; fixedOrigin = origin;
        rp = RelyingParty.builder().identity(RelyingPartyIdentity.builder().id("localhost").name("Flare local lab").build())
                .credentialRepository(credentials).origins(Set.of(origin))
                .allowOriginPort(false).allowOriginSubdomain(false)
                .preferredPubkeyParams(List.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256))
                .attestationConveyancePreference(AttestationConveyancePreference.NONE).build();
    }

    synchronized Options registerOptions(Context context) {
        check(context);
        if (credentials.credential != null || registrationStarted) throw invalid();
        var options = rp.startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder().name(credentials.actor).displayName("Disposable Flare lab owner")
                        .id(credentials.handle).build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.DISCOURAGED)
                        .userVerification(UserVerificationRequirement.REQUIRED).build()).build());
        try {
            Options result = save(context, "REGISTER", "EMAIL_CHANGE", "readiness-only@example.test", options.toJson(), options.toCredentialsCreateJson());
            registrationStarted = true;
            return result;
        }
        catch (Exception failure) { throw invalid(); }
    }

    synchronized Map<String, Object> registerFinish(Context context, String ref, String response) {
        check(context);
        if (credentials.credential != null) throw invalid();
        Pending pending = pending(context, ref, "REGISTER", "EMAIL_CHANGE", "readiness-only@example.test");
        try {
            var result = rp.finishRegistration(FinishRegistrationOptions.builder()
                    .request(PublicKeyCredentialCreationOptions.fromJson(pending.requestJson()))
                    .response(PublicKeyCredential.parseRegistrationResponseJson(bounded(response))).build());
            if (!result.isUserVerified() || !take(ref, pending)) throw invalid();
            credentials.credential = RegisteredCredential.builder().credentialId(result.getKeyId().getId())
                    .userHandle(credentials.handle).publicKeyCose(result.getPublicKeyCose())
                    .signatureCount(result.getSignatureCount()).build();
            enrolledContext = context; backupEligible = result.isBackupEligible(); backedUp = result.isBackedUp();
            // Verification and one-use consumption precede publication. A publication failure
            // keeps the enrollment slot closed; it must never cause another device creation.
            enrollmentRecorder.record(Map.ofEntries(
                    Map.entry("schema_version", 1),
                    Map.entry("record_kind", "VERIFIED_LAB_REGISTRATION_PUBLIC_ONLY"),
                    Map.entry("rp_id", "localhost"), Map.entry("origin", fixedOrigin),
                    Map.entry("lab_actor", credentials.actor),
                    Map.entry("user_handle_b64url", credentials.handle.getBase64Url()),
                    Map.entry("credential_id_b64url", credentials.credential.getCredentialId().getBase64Url()),
                    Map.entry("public_key_cose_b64url", credentials.credential.getPublicKeyCose().getBase64Url()),
                    Map.entry("signature_count_at_registration", credentials.credential.getSignatureCount()),
                    Map.entry("verified_at_epoch_ms", clock.getAsLong()), Map.entry("user_verified", true),
                    Map.entry("backup_eligible", backupEligible), Map.entry("backed_up", backedUp),
                    Map.entry("hardware_attestation_trusted", false), Map.entry("human_identity_proven", false)));
            return browserStatus();
        } catch (Exception failure) { throw invalid(); }
    }

    synchronized Options assertionOptions(Context context, String action, String target) {
        check(context);
        if (enrollmentOnly || credentials.credential == null || assertions >= (restored ? 1 : 2)
                || (enrolledContext != null && context.session().equals(enrolledContext.session()))) throw invalid();
        var request = rp.startAssertion(StartAssertionOptions.builder().username(credentials.actor)
                .userVerification(UserVerificationRequirement.REQUIRED).build());
        try { return save(context, "ASSERT", action, target, request.toJson(), request.toCredentialsGetJson()); }
        catch (Exception failure) { throw invalid(); }
    }

    synchronized Verified assertionFinish(Context context, String action, String target, String ref, String response) {
        check(context);
        if (enrollmentOnly || credentials.credential == null || assertions >= (restored ? 1 : 2)) throw invalid();
        Pending pending = pending(context, ref, "ASSERT", action, target);
        try {
            var result = rp.finishAssertion(FinishAssertionOptions.builder()
                    .request(AssertionRequest.fromJson(pending.requestJson()))
                    .response(PublicKeyCredential.parseAssertionResponseJson(bounded(response))).build());
            if (!result.isSuccess() || !result.isUserVerified() || !take(ref, pending)) throw invalid();
            credentials.credential = credentials.credential.toBuilder().signatureCount(result.getSignatureCount()).build();
            assertions++; backupEligible = result.isBackupEligible(); backedUp = result.isBackedUp();
            return new Verified(new Evidence("VERIFIED", "WEBAUTHN_ONE_USE_SCOPED_ASSERTION",
                    Math.max(0, (clock.getAsLong() - pending.scope().issuedAt()) / 1000.0), true),
                    true, backupEligible, backedUp);
        } catch (Exception failure) { throw invalid(); }
    }

    synchronized Map<String, Object> status() {
        return Map.of("registered_credentials", credentials.credential == null ? 0 : 1,
                "successful_assertions", assertions, "backup_eligible", backupEligible,
                "backed_up", backedUp, "user_verified", credentials.credential != null,
                "human_identity_proven", false, "hardware_attestation_trusted", false,
                "sensitive_attempts", 0, "fit_calls", 0, "registration_ceremony_started", registrationStarted);
    }

    synchronized boolean configured() { return rp != null && (!restored || Math.floorDiv(clock.getAsLong(), 1000) >= restoredSessionFloor); }

    synchronized Map<String, Object> browserStatus() {
        var result = new LinkedHashMap<>(status());
        result.put("remaining_ms", rp == null ? 0L : Math.max(0L, deadline - clock.getAsLong()));
        result.put("lifecycle_phase", restored ? "RESTORED_ASSERTION" : enrollmentOnly ? "ENROLL_ONLY" : "READINESS");
        return result;
    }

    private void check(Context context) {
        if (rp == null || context == null || !Objects.equals(credentials.actor, context.actor())
                || clock.getAsLong() >= deadline) throw invalid();
        if (restored) {
            try {
                long issued = Instant.parse(context.issuedAt()).getEpochSecond();
                if (issued < restoredSessionFloor || issued > Math.floorDiv(clock.getAsLong(), 1000)) throw invalid();
            } catch (Exception failure) { throw invalid(); }
        }
    }

    private Options save(Context context, String kind, String action, String target, String request, String publicKey) throws Exception {
        if (++requests > 16) throw invalid();
        String ref = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes()); long now = clock.getAsLong();
        var pending = new Pending(new Ticket(context, action, targetDigest(action, target), now,
                Math.min(now + 300_000, deadline)), kind, request);
        store.put(key(ref), json.writeValueAsString(pending), pending.scope().expiresAt());
        return new Options(ref, publicKey);
    }

    private Pending pending(Context context, String ref, String kind, String action, String target) {
        if (ref == null || !ref.matches("[A-Za-z0-9_-]{43}")) throw invalid();
        try {
            String value = store.get(key(ref)); if (value == null || value.length() > 32_768) throw invalid();
            Pending pending = json.readValue(value, Pending.class); Ticket t = pending.scope();
            if (!kind.equals(pending.kind()) || !context.equals(t.context()) || !action.equals(t.action())
                    || !MessageDigest.isEqual(t.targetDigest().getBytes(StandardCharsets.US_ASCII),
                            targetDigest(action, target).getBytes(StandardCharsets.US_ASCII))
                    || t.issuedAt() > clock.getAsLong() || t.expiresAt() <= clock.getAsLong()
                    || t.expiresAt() - t.issuedAt() > 300_000) throw invalid();
            return pending;
        } catch (Exception failure) { throw invalid(); }
    }

    private boolean take(String ref, Pending pending) throws Exception {
        return store.take(key(ref), json.writeValueAsString(pending), pending.scope().expiresAt());
    }

    private String targetDigest(String action, String target) throws Exception {
        if (!Set.of("EMAIL_CHANGE", "PASSWORD_CHANGE").contains(action) || target == null || target.isBlank() || target.length() > 512) throw invalid();
        String value = action.equals("EMAIL_CHANGE") ? target.trim().toLowerCase(Locale.ROOT) : target;
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(targetKey, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal((action + "\u0000" + value).getBytes(StandardCharsets.UTF_8)));
    }
    private static String bounded(String response) {
        if (response == null || response.length() > 65_536) throw invalid(); return response;
    }
    private byte[] randomBytes() { byte[] b = new byte[32]; random.nextBytes(b); return b; }
    private static String key(String ref) {
        try { return "lab:ueba:webauthn:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(ref.getBytes(StandardCharsets.US_ASCII))); }
        catch (Exception failure) { throw new IllegalStateException(failure); }
    }
    private static BadRequestException invalid() { return new BadRequestException("Invalid or expired WebAuthn lab ceremony."); }

    private static final class Repository implements CredentialRepository {
        private String actor;
        private ByteArray handle;
        private RegisteredCredential credential;
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            return Objects.equals(actor, username) && credential != null
                    ? Set.of(PublicKeyCredentialDescriptor.builder().id(credential.getCredentialId()).build()) : Set.of();
        }
        public Optional<ByteArray> getUserHandleForUsername(String username) { return Objects.equals(actor, username) ? Optional.of(handle) : Optional.empty(); }
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) { return Objects.equals(handle, userHandle) ? Optional.of(actor) : Optional.empty(); }
        public Optional<RegisteredCredential> lookup(ByteArray id, ByteArray userHandle) {
            return credential != null && credential.getCredentialId().equals(id) && handle.equals(userHandle) ? Optional.of(credential) : Optional.empty();
        }
        public Set<RegisteredCredential> lookupAll(ByteArray id) { return credential != null && credential.getCredentialId().equals(id) ? Set.of(credential) : Set.of(); }
    }
}
