package com.flarefitness.backend.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private IpAddressResolver ipAddressResolver;

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = new AuthController(authService, ipAddressResolver, "flare_auth", false);
    }

    @Test
    void logoutRevokesCurrentTokenWithoutSendingAStaleCookieDeletion() {
        when(request.getAttribute(JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE))
                .thenReturn("customer-token");

        ResponseEntity<Void> response = controller.logout(null, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeaders()).doesNotContainKey(HttpHeaders.SET_COOKIE);
        verify(authService).logout("customer-token");
    }

    @Test
    void logoutAllRevokesServerSessionsWithoutSendingAStaleCookieDeletion() {
        when(authentication.getName()).thenReturn("customer");

        ResponseEntity<Void> response = controller.logoutAll(authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeaders()).doesNotContainKey(HttpHeaders.SET_COOKIE);
        verify(authService).logoutAll("customer");
    }
}
