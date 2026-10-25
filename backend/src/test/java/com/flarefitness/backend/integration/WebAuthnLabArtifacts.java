package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.JsonParser;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.upokecenter.cbor.CBORObject;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import java.util.HashSet;

/** The existing harness publication protocol, shared with the synthetic persistence tests. */
final class WebAuthnLabArtifacts {
    private WebAuthnLabArtifacts() { }
    record Enrollment(RegisteredCredential credential, boolean backupEligible, boolean backedUp) { }
    private static final Set<String> RECORD_FIELDS = Set.of("schema_version", "record_kind", "rp_id", "origin", "lab_actor",
            "user_handle_b64url", "credential_id_b64url", "public_key_cose_b64url", "signature_count_at_registration",
            "verified_at_epoch_ms", "user_verified", "backup_eligible", "backed_up", "hardware_attestation_trusted", "human_identity_proven");

    static String publish(Path output, ObjectMapper json, String name, Object value) throws Exception {
        if (!name.matches("[a-z0-9][a-z0-9.-]*\\.private\\.json"))
            throw new IllegalArgumentException("Fixed lab artifact basename required");
        Path directory = privateDirectory(output);
        byte[] bytes = json.writeValueAsBytes(value);
        if (bytes.length >= 65_536) throw new IllegalArgumentException("Lab artifact byte cap exceeded");
        try (var channel = FileChannel.open(directory.resolve(name), Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            var buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        try (var parent = FileChannel.open(directory, StandardOpenOption.READ)) { parent.force(true); }
        return sha256(bytes);
    }

    /** The expected marker hash is supplied by the trusted supervisor, never by an HTTP caller. */
    static Enrollment readVerified(Path output, ObjectMapper json, String expectedMarkerHash,
                                   String actor, String origin, long now) throws Exception {
        if (expectedMarkerHash == null || !expectedMarkerHash.matches("[a-f0-9]{64}")) throw invalid();
        Path directory = privateDirectory(output);
        byte[] markerBytes = privateFile(directory.resolve("verified-enrollment.commit.private.json"));
        if (!sha256(markerBytes).equals(expectedMarkerHash)) throw invalid();
        ObjectMapper strict = json.copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        JsonNode marker = strict.readTree(markerBytes);
        if (!fields(marker).equals(Set.of("receipt", "receipt_sha256"))
                || !text(marker, "receipt").equals("verified-enrollment.receipt.private.json")) throw invalid();
        byte[] receiptBytes = privateFile(directory.resolve("verified-enrollment.receipt.private.json"));
        if (!sha256(receiptBytes).equals(text(marker, "receipt_sha256"))) throw invalid();
        JsonNode record = strict.readTree(receiptBytes);
        if (!fields(record).equals(RECORD_FIELDS) || number(record, "schema_version") != 1
                || !text(record, "record_kind").equals("VERIFIED_LAB_REGISTRATION_PUBLIC_ONLY")
                || !text(record, "rp_id").equals("localhost") || !text(record, "origin").equals(origin)
                || !text(record, "lab_actor").equals(actor) || !flag(record, "user_verified")
                || flag(record, "hardware_attestation_trusted") || flag(record, "human_identity_proven")) throw invalid();
        long verified = number(record, "verified_at_epoch_ms"), count = number(record, "signature_count_at_registration");
        if (verified < 0 || verified > now || count < 0 || count > 0xffff_ffffL) throw invalid();
        boolean eligible = flag(record, "backup_eligible"), backedUp = flag(record, "backed_up");
        if (backedUp && !eligible) throw invalid();
        var id = ByteArray.fromBase64Url(text(record, "credential_id_b64url"));
        var handle = ByteArray.fromBase64Url(text(record, "user_handle_b64url"));
        var cose = ByteArray.fromBase64Url(text(record, "public_key_cose_b64url"));
        if (id.getBytes().length == 0 || id.getBytes().length > 1024 || handle.getBytes().length == 0
                || handle.getBytes().length > 64 || cose.getBytes().length > 8192) throw invalid();
        int algorithm = CBORObject.DecodeFromBytes(cose.getBytes()).get(CBORObject.FromObject(3)).AsInt32();
        if (algorithm != -7 && algorithm != -257) throw invalid();
        var credential = RegisteredCredential.builder().credentialId(id).userHandle(handle).publicKeyCose(cose)
                .signatureCount(count).build();
        credential.getParsedPublicKey();
        return new Enrollment(credential, eligible, backedUp);
    }

    private static Path privateDirectory(Path output) throws Exception {
        Path directory = output.toAbsolutePath().normalize();
        for (Path p = directory; p != null; p = p.getParent())
            if (Files.isSymbolicLink(p)) throw new IllegalArgumentException("Symlink artifact directory refused");
        var permissions = Files.getPosixFilePermissions(directory);
        String processUser = ProcessHandle.current().info().user().orElseThrow();
        var processOwner = directory.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(processUser);
        if (!Files.isDirectory(directory) || permissions.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))
                || !Files.getOwner(directory).equals(processOwner))
            throw new IllegalArgumentException("Owner-private lab directory required");
        return directory;
    }

    private static byte[] privateFile(Path path) throws Exception {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) >= 65_536
                || ((Number) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).intValue() != 1) throw invalid();
        String processUser = ProcessHandle.current().info().user().orElseThrow();
        var owner = path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(processUser);
        if (!Files.getOwner(path).equals(owner) || Files.getPosixFilePermissions(path).stream()
                .anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) throw invalid();
        try (var channel = FileChannel.open(path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            var bytes = ByteBuffer.allocate(65_536);
            while (bytes.hasRemaining() && channel.read(bytes) != -1) { }
            if (!bytes.hasRemaining()) throw invalid();
            return java.util.Arrays.copyOf(bytes.array(), bytes.position());
        }
    }

    private static Set<String> fields(JsonNode node) {
        if (node == null || !node.isObject()) throw invalid();
        var names = new HashSet<String>(); node.fieldNames().forEachRemaining(names::add); return names;
    }
    private static String text(JsonNode node, String name) {
        if (!node.path(name).isTextual()) throw invalid(); return node.path(name).textValue();
    }
    private static long number(JsonNode node, String name) {
        if (!node.path(name).isIntegralNumber() || !node.path(name).canConvertToLong()) throw invalid(); return node.path(name).longValue();
    }
    private static boolean flag(JsonNode node, String name) {
        if (!node.path(name).isBoolean()) throw invalid(); return node.path(name).booleanValue();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid trusted lab enrollment record"); }

    static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
