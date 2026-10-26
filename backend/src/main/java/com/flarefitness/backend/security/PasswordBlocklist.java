package com.flarefitness.backend.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** A single compact array; password values never leave this process or become map keys. */
final class PasswordBlocklist {
    private static final int WIDTH = 32;
    private static final int EXPECTED_BYTES = 1_492_480;
    private static final String CHECKSUM = "a1e2a00500808fa829c5bb1f5ac7583be48234d8c06d4a2cd014b95f424ba865";
    private static final byte[] DATA = load();

    private PasswordBlocklist() { }

    static boolean contains(String password) {
        byte[] digest = sha256(password.getBytes(StandardCharsets.UTF_8));
        int low = 0, high = DATA.length / WIDTH - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            int comparison = 0;
            for (int i = 0; i < WIDTH && comparison == 0; i++) {
                comparison = Integer.compare(Byte.toUnsignedInt(digest[i]), Byte.toUnsignedInt(DATA[middle * WIDTH + i]));
            }
            if (comparison == 0) return true;
            if (comparison < 0) high = middle - 1; else low = middle + 1;
        }
        return false;
    }

    private static byte[] load() {
        try (var input = PasswordBlocklist.class.getResourceAsStream("/security/password-blocklist.bin")) {
            if (input == null) throw new IllegalStateException("Required offline password blocklist is missing");
            byte[] data = input.readNBytes(EXPECTED_BYTES + 1);
            if (data.length != EXPECTED_BYTES || !CHECKSUM.equals(HexFormat.of().formatHex(sha256(data)))) {
                throw new IllegalStateException("Offline password blocklist failed its integrity check");
            }
            return data;
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot load the offline password blocklist", failure);
        }
    }
    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
