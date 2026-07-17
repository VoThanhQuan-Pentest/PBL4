package com.flarefitness.backend.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Keeps bearer tokens and other sensitive identifiers out of Redis key names.
 * JWTs are high-entropy values, so a SHA-256 fingerprint is sufficient for a
 * lookup key while avoiding disclosure in Redis dumps and diagnostics.
 */
public final class TokenFingerprint {

    private TokenFingerprint() {
    }

    public static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(String.valueOf(value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available on this JVM.", exception);
        }
    }
}
