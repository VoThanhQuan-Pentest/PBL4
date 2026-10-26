package com.flarefitness.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.Cookie;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String CURRENT_TOKEN_REQUEST_ATTRIBUTE =
            JwtAuthenticationFilter.class.getName() + ".CURRENT_TOKEN";
    public static final String SESSION_TELEMETRY_REQUEST_ATTRIBUTE =
            JwtAuthenticationFilter.class.getName() + ".SESSION_TELEMETRY";

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.flarefitness.backend.service.siem.SecurityEventService investigationEvents;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private IpAddressResolver investigationIp;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.flarefitness.backend.service.siem.SiemSessionRevocationEvidence revocationEvidence;
    private final JwtTokenService jwtTokenService;
    private final RedisTokenStore redisTokenStore;
    private final CustomUserDetailsService userDetailsService;
    private final String cookieName;

    public JwtAuthenticationFilter(
            JwtTokenService jwtTokenService,
            RedisTokenStore redisTokenStore,
            CustomUserDetailsService userDetailsService,
            @org.springframework.beans.factory.annotation.Value("${app.security.auth-cookie-name}") String cookieName
    ) {
        this.jwtTokenService = jwtTokenService;
        this.redisTokenStore = redisTokenStore;
        this.userDetailsService = userDetailsService;
        this.cookieName = cookieName;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = extractBearerToken(request);
        if (token != null
                && jwtTokenService.isValid(token)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String username = jwtTokenService.extractUsername(token);
            String storedUsername = redisTokenStore.findUsername(token);
            if (storedUsername == null || !storedUsername.equalsIgnoreCase(username)) {
                observeUnallowedToken(request,token,username);
                filterChain.doFilter(request, response);
                return;
            }
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (!(userDetails instanceof CurrentUserPrincipal principal)
                    || !principal.getUser().getId().equals(jwtTokenService.extractUserId(token))
                    || !java.util.Objects.equals(
                            principal.getUser().getAuthVersion() == null ? 0L : principal.getUser().getAuthVersion(),
                            jwtTokenService.extractAuthVersion(token))) {
                observeUnallowedToken(request,token,username);
                filterChain.doFilter(request, response);
                return;
            }
            if (!userDetails.isEnabled() || !userDetails.isAccountNonLocked()) {
                observeUnallowedToken(request,token,username);
                redisTokenStore.revokeAll(username);
                filterChain.doFilter(request, response);
                return;
            }

            if ("1".equals(request.getHeader("X-User-Activity"))) redisTokenStore.renewIdle(token);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute(CURRENT_TOKEN_REQUEST_ATTRIBUTE, token);
            jwtTokenService.extractSessionTelemetry(token, principal.getUser().getId())
                    .ifPresent(metadata -> request.setAttribute(SESSION_TELEMETRY_REQUEST_ATTRIBUTE, metadata));
        }

        filterChain.doFilter(request, response);
    }

    private void observeUnallowedToken(HttpServletRequest request,String token,String username) {
        if(investigationEvents==null)return;
        try {
            var details=userDetailsService.loadUserByUsername(username);
            if(!(details instanceof CurrentUserPrincipal principal)||!principal.getUser().getId().equals(jwtTokenService.extractUserId(token)))return;
            long current=principal.getUser().getAuthVersion()==null?0:principal.getUser().getAuthVersion();
            boolean revoked=current>jwtTokenService.extractAuthVersion(token);
            boolean isolated=principal.getUser().isSocIsolationActive();
            String reference="auth-version:"+current;
            String explicit=revocationEvidence==null?null:revocationEvidence.find(token,principal.getUser().getId());
            String reason=isolated?"ACCOUNT_ISOLATED":revoked?"AUTH_VERSION_REVOKED":explicit!=null?"SESSION_REVOKED":"SESSION_NOT_ALLOWLISTED";
            if(explicit!=null)reference=explicit;
            investigationEvents.recordSessionDenial(principal.getUser().getId(),reason,reference,
                    investigationIp==null?request.getRemoteAddr():investigationIp.resolve(request),request.getHeader("User-Agent"));
        }catch(RuntimeException telemetryUnavailable){/* This observation never changes an authentication result. */}
    }
    private String extractBearerToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName()) && StringUtils.hasText(cookie.getValue())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
