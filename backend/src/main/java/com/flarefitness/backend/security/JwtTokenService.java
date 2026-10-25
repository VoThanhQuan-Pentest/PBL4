package com.flarefitness.backend.security;

import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

    private final SecretKey secretKey;
    private final long expirationSeconds;

    public JwtTokenService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-seconds}") long expirationSeconds
    ) {
        String normalizedSecret = String.valueOf(secret == null ? "" : secret).toLowerCase(java.util.Locale.ROOT);
        if (secret == null
                || secret.isBlank()
                || "replace-this-secret-with-at-least-32-characters".equals(secret)
                || normalizedSecret.contains("replace")
                || normalizedSecret.contains("change-this")
                || secret.length() < 32) {
            throw new IllegalStateException("APP_JWT_SECRET must be configured with a non-default value of at least 32 characters.");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationSeconds = expirationSeconds;
    }

    public String generateToken(CurrentUserPrincipal principal) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(expirationSeconds);

        return Jwts.builder()
                .subject(principal.getUsername())
                .claim("role", principal.getUser().getRole())
                .claim("user_id", principal.getUser().getId())
                .claim("auth_version", principal.getUser().getAuthVersion() == null
                        ? 0L : principal.getUser().getAuthVersion())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public String extractUserId(String token) {
        return extractClaims(token).get("user_id", String.class);
    }

    public long extractAuthVersion(String token) {
        Object value = extractClaims(token).get("auth_version");
        return value instanceof Number number ? number.longValue() : 0L;
    }

    /** Claim provenance only: this does not authenticate or allowlist the session. */
    public Instant verifiedIssuedAt(String token) {return extractClaims(token).getIssuedAt().toInstant();}

    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    /** Additive telemetry only; caller must finish allowlist/account checks before attaching it. */
    public Optional<UebaSessionTelemetry> extractSessionTelemetry(String token, String actorId) {
        if (token == null || token.length() > 16_384) return Optional.empty();
        try {
            Claims claims = extractClaims(token);
            if (!java.util.Objects.equals(actorId, claims.get("user_id", String.class))) return Optional.empty();
            Date issuedAt = claims.getIssuedAt();
            return UebaSessionTelemetry.fromVerifiedClaims(actorId, claims.getId(),
                    issuedAt == null ? null : issuedAt.toInstant());
        } catch (Exception invalidMetadata) {
            // Invalid/missing legacy metadata never changes authentication or leaks claim values.
            return Optional.empty();
        }
    }

    public boolean isValid(String token) {
        try {
            Claims claims = extractClaims(token);
            return claims.getExpiration().after(new Date());
        } catch (Exception exception) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
