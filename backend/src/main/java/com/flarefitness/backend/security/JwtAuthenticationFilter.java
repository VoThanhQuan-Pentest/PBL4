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
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.Cookie;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String CURRENT_TOKEN_REQUEST_ATTRIBUTE =
            JwtAuthenticationFilter.class.getName() + ".CURRENT_TOKEN";

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
                filterChain.doFilter(request, response);
                return;
            }
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (!userDetails.isEnabled() || !userDetails.isAccountNonLocked()) {
                redisTokenStore.revokeAll(username);
                filterChain.doFilter(request, response);
                return;
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute(CURRENT_TOKEN_REQUEST_ATTRIBUTE, token);
        }

        filterChain.doFilter(request, response);
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
