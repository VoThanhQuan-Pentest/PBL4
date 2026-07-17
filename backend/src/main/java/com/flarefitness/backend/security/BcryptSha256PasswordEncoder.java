package com.flarefitness.backend.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * BCrypt only incorporates the first 72 bytes of a password.  New hashes use
 * a versioned SHA-256 pre-hash so the documented 12–128 character policy is
 * meaningful, while bare BCrypt hashes from existing accounts remain valid
 * and are upgraded after a successful login.
 */
public final class BcryptSha256PasswordEncoder implements PasswordEncoder {

    public static final String PREFIX = "{bcrypt-sha256}";

    private final BCryptPasswordEncoder bcrypt;

    public BcryptSha256PasswordEncoder(int strength) {
        this.bcrypt = new BCryptPasswordEncoder(strength);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return PREFIX + bcrypt.encode(prehash(rawPassword));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }
        if (encodedPassword.startsWith(PREFIX)) {
            return bcrypt.matches(prehash(rawPassword), encodedPassword.substring(PREFIX.length()));
        }
        return bcrypt.matches(rawPassword, encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }
        if (!encodedPassword.startsWith(PREFIX)) {
            // Migrate every bare BCrypt value to the version that does not
            // silently truncate passwords longer than 72 bytes.
            return true;
        }
        return bcrypt.upgradeEncoding(encodedPassword.substring(PREFIX.length()));
    }

    private String prehash(CharSequence rawPassword) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(String.valueOf(rawPassword == null ? "" : rawPassword).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available on this JVM.", exception);
        }
    }
}
