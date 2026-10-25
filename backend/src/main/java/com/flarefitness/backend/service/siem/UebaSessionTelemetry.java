package com.flarefitness.backend.service.siem;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/** Sanitized metadata only: never retains a token or its raw random identifier. */
public record UebaSessionTelemetry(String sessionPseudonym, LocalDateTime sessionIssuedAt) {
    public static final int CONTRACT_VERSION = 3;
    /** Additive login/action association; the historical HTTP contract remains version 3. */
    public static final int POST_LOGIN_CONTRACT_VERSION = 4;
    private static final byte[] DOMAIN = "flare-ueba-session-v1\u0000".getBytes(StandardCharsets.UTF_8);

    public UebaSessionTelemetry {
        if (sessionPseudonym == null || !sessionPseudonym.matches("[0-9a-f]{64}") || sessionIssuedAt == null) {
            throw new IllegalArgumentException("Invalid sanitized session telemetry");
        }
    }

    /**
     * Caller MUST have verified signature, Redis allowlist, user ID, auth version and account state first.
     * Legacy/malformed metadata is omitted without changing authentication acceptance.
     */
    public static Optional<UebaSessionTelemetry> fromVerifiedClaims(String actorId, String jti, Instant issued) {
        if (actorId == null || actorId.isBlank() || actorId.length() > 64
                || jti == null || jti.length() != 36 || issued == null) return Optional.empty();
        try {
            UUID randomId = UUID.fromString(jti);
            if (!randomId.toString().equals(jti) || randomId.version() != 4 || randomId.variant() != 2) {
                return Optional.empty();
            }
            long epochSeconds = issued.getEpochSecond();
            if (epochSeconds <= 0 || epochSeconds > Instant.now().getEpochSecond()) return Optional.empty();
            LocalDateTime issuedAt = LocalDateTime.ofInstant(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC);
            MessageDigest hash = sha256();
            byte[] actor = actorId.getBytes(StandardCharsets.UTF_8);
            byte[] session = jti.getBytes(StandardCharsets.UTF_8);
            hash.update(DOMAIN);
            hash.update(ByteBuffer.allocate(Integer.BYTES).putInt(actor.length).array());
            hash.update(actor);
            hash.update(ByteBuffer.allocate(Integer.BYTES).putInt(session.length).array());
            hash.update(session);
            return Optional.of(new UebaSessionTelemetry(HexFormat.of().formatHex(hash.digest()), issuedAt));
        } catch (Exception invalidMetadata) {
            // Deliberately do not log claim values, tokens, or parser exception messages.
            return Optional.empty();
        }
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA-256 unavailable"); }
    }
}
