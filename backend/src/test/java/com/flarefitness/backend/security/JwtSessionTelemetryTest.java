package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class JwtSessionTelemetryTest {
    private static final String SECRET = "test-only-session-telemetry-secret-at-least-thirty-two-characters";
    private final JwtTokenService tokens = new JwtTokenService(SECRET, 3600);
    private final RedisTokenStore allowlist = mock(RedisTokenStore.class);
    private final CustomUserDetailsService users = mock(CustomUserDetailsService.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(tokens, allowlist, users, "auth");
    private final CurrentUserPrincipal principal = principal();

    @BeforeEach @AfterEach
    void clearContext() { SecurityContextHolder.clearContext(); }

    @Test
    void onlyFullyAcceptedSignedSessionAttachesSanitizedMetadata() throws Exception {
        String token = tokens.generateToken(principal);
        accept(token);
        MockHttpServletRequest request = filter(token);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isSameAs(principal);
        UebaSessionTelemetry metadata = (UebaSessionTelemetry)
                request.getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE);
        assertThat(metadata.sessionPseudonym()).matches("[0-9a-f]{64}");
        assertThat(metadata.sessionIssuedAt().toInstant(ZoneOffset.UTC)).isBeforeOrEqualTo(Instant.now());
        assertThat(metadata.toString()).doesNotContain(token, principal.getUsername());
        assertThat(tokens.extractSessionTelemetry(token, "other-actor")).isEmpty();
    }

    @Test
    void signatureAndAllowlistDenialsNeverAttachMetadata() throws Exception {
        assertThat(filter("not-a-signed-token")
                .getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        verifyNoInteractions(allowlist, users);
        String token = tokens.generateToken(principal);
        assertThat(filter(token).getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(users);
        assertThat(tokens.extractSessionTelemetry("x".repeat(16_385), principal.getUser().getId())).isEmpty();
    }

    @Test
    void userIdAuthVersionAndAccountDenialsNeverAttachMetadata() throws Exception {
        String token = tokens.generateToken(principal);
        accept(token);
        principal.getUser().setId("different-id");
        assertThat(filter(token).getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        principal.getUser().setId("customer-1");
        principal.getUser().setAuthVersion(1L);
        assertThat(filter(token).getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        principal.getUser().setAuthVersion(0L);
        principal.getUser().setDeleted(true);
        assertThat(filter(token).getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void legacyOrInvalidSessionMetadataDoesNotChangeAuthentication() throws Exception {
        for (String token : new String[] { signed(null, null), signed("not-random", Instant.now().minusSeconds(1)),
                signed(UUID.randomUUID().toString(), Instant.now().plusSeconds(3600)) }) {
            SecurityContextHolder.clearContext();
            accept(token);
            MockHttpServletRequest request = filter(token);
            assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isSameAs(principal);
            assertThat(request.getAttribute(JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE)).isEqualTo(token);
            assertThat(request.getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)).isNull();
        }
    }

    private String signed(String jti, Instant issuedAt) {
        var builder = Jwts.builder().subject(principal.getUsername())
                .claim("user_id", principal.getUser().getId()).claim("auth_version", 0L)
                .expiration(Date.from(Instant.now().plusSeconds(7200)));
        if (jti != null) builder.id(jti);
        if (issuedAt != null) builder.issuedAt(Date.from(issuedAt));
        return builder.signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8))).compact();
    }

    private void accept(String token) {
        when(allowlist.findUsername(token)).thenReturn(principal.getUsername());
        when(users.loadUserByUsername(principal.getUsername())).thenReturn(principal);
    }

    private MockHttpServletRequest filter(String token) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/products");
        request.addHeader("Authorization", "Bearer " + token);
        request.addHeader("X-Session-Pseudonym", "forged");
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> { });
        return request;
    }

    private static CurrentUserPrincipal principal() {
        User user = new User(); user.setId("customer-1"); user.setUsername("session-owner");
        user.setRole("CUSTOMER"); user.setAuthVersion(0L); user.setDeleted(false); user.setStatus("Hoat dong");
        return new CurrentUserPrincipal(user);
    }
}
