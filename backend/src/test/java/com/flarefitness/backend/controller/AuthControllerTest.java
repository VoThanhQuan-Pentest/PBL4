package com.flarefitness.backend.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.ArgumentMatchers.anyString;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).isNull();
        verify(authService).logout("customer-token");
    }

    @Test
    void logoutAllRevokesServerSessionsWithoutSendingAStaleCookieDeletion() {
        when(authentication.getName()).thenReturn("customer");

        ResponseEntity<Void> response = controller.logoutAll(authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).isNull();
        verify(authService).logoutAll("customer");
    }

    @Test void successfulLegacyAuthenticationRetiresOnlyThePresentedAuthenticatedSession() {
        var login = new com.flarefitness.backend.dto.auth.LoginRequest("customer", "Synthetic!Passphrase1");
        when(ipAddressResolver.resolve(request)).thenReturn("192.0.2.185");
        when(request.getAttribute(JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE)).thenReturn("previous-session");
        when(authService.login(login, "192.0.2.185", null))
                .thenReturn(new com.flarefitness.backend.dto.auth.LoginResponse("replacement-session", 3600, null));
        var response = controller.login(login, request);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).contains("flare_auth=replacement-session");
        var order = inOrder(authService);
        order.verify(authService).login(login, "192.0.2.185", null);
        order.verify(authService).retirePreviousSession("previous-session");
        verify(authService, never()).logout(anyString());
        verify(authService, never()).logoutAll(anyString());
    }

    @Test void aFailedPasswordProofDoesNotRetireTheCurrentSession() {
        var login = new com.flarefitness.backend.dto.auth.LoginRequest("customer", "Wrong!Passphrase1");
        when(ipAddressResolver.resolve(request)).thenReturn("192.0.2.186");
        when(authService.login(login, "192.0.2.186", null))
                .thenThrow(new com.flarefitness.backend.exception.UnauthorizedException("Invalid credentials"));
        assertThatThrownBy(() -> controller.login(login, request))
                .isInstanceOf(com.flarefitness.backend.exception.UnauthorizedException.class);
        verify(authService, never()).retirePreviousSession(anyString());
    }

    @Test void anUnvalidatedAuthorizationHeaderCannotSelectASessionToRetire() {
        var servletRequest = new org.springframework.mock.web.MockHttpServletRequest();
        servletRequest.addHeader(HttpHeaders.AUTHORIZATION, "Bearer unvalidated-token");
        var login = new com.flarefitness.backend.dto.auth.LoginRequest("customer", "Synthetic!Passphrase1");
        when(ipAddressResolver.resolve(servletRequest)).thenReturn("192.0.2.187");
        when(authService.login(login, "192.0.2.187", null))
                .thenReturn(new com.flarefitness.backend.dto.auth.LoginResponse("replacement-session", 3600, null));
        assertThat(controller.login(login, servletRequest).getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(authService, never()).retirePreviousSession(anyString());
    }
}
