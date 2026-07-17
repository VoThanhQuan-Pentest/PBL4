package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.auth.AuthMessageResponse;
import com.flarefitness.backend.dto.auth.CurrentUserResponse;
import com.flarefitness.backend.dto.auth.ForgotPasswordOtpVerifyRequest;
import com.flarefitness.backend.dto.auth.ForgotPasswordRequest;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.dto.auth.LoginResponse;
import com.flarefitness.backend.dto.auth.OtpRequest;
import com.flarefitness.backend.dto.auth.PasswordResetVerificationResponse;
import com.flarefitness.backend.dto.auth.RegisterRequest;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.web.csrf.CsrfToken;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final IpAddressResolver ipAddressResolver;
    private final String cookieName;
    private final boolean cookieSecure;

    public AuthController(
            AuthService authService,
            IpAddressResolver ipAddressResolver,
            @org.springframework.beans.factory.annotation.Value("${app.security.auth-cookie-name}") String cookieName,
            @org.springframework.beans.factory.annotation.Value("${app.security.auth-cookie-secure}") boolean cookieSecure
    ) {
        this.authService = authService;
        this.ipAddressResolver = ipAddressResolver;
        this.cookieName = cookieName;
        this.cookieSecure = cookieSecure;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return loginResponse(authService.login(request, ipAddressResolver.resolve(httpServletRequest)));
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken csrfToken) {
        return Map.of("token", csrfToken.getToken());
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        return loginResponse(authService.register(request));
    }

    @PostMapping("/register/otp")
    public ResponseEntity<AuthMessageResponse> sendRegisterOtp(
            @Valid @RequestBody OtpRequest request,
            HttpServletRequest httpServletRequest
    ) {
        authService.sendRegisterOtp(request, ipAddressResolver.resolve(httpServletRequest));
        return ResponseEntity.ok(new AuthMessageResponse("Mã OTP đăng ký đã được gửi đến email."));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<AuthMessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.ok(new AuthMessageResponse("Đặt lại mật khẩu thành công. Bạn có thể đăng nhập lại ngay."));
    }

    @PostMapping("/forgot-password/otp")
    public ResponseEntity<AuthMessageResponse> sendForgotPasswordOtp(
            @Valid @RequestBody OtpRequest request,
            HttpServletRequest httpServletRequest
    ) {
        authService.sendForgotPasswordOtp(request, ipAddressResolver.resolve(httpServletRequest));
        return ResponseEntity.ok(new AuthMessageResponse("Mã OTP đặt lại mật khẩu đã được gửi đến email."));
    }

    @PostMapping("/forgot-password/otp/verify")
    public ResponseEntity<PasswordResetVerificationResponse> verifyForgotPasswordOtp(
            @Valid @RequestBody ForgotPasswordOtpVerifyRequest request
    ) {
        return ResponseEntity.ok(authService.verifyForgotPasswordOtp(request));
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> me(Authentication authentication) {
        return ResponseEntity.ok(authService.getCurrentUser(authentication.getName()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            HttpServletRequest httpServletRequest
    ) {
        String token = currentToken(httpServletRequest, authorizationHeader);
        if (token != null) {
            authService.logout(token);
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, expiredCookie().toString())
                .build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(Authentication authentication) {
        authService.logoutAll(authentication.getName());
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, expiredCookie().toString())
                .build();
    }

    private ResponseEntity<LoginResponse> loginResponse(LoginResponse response) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, response.accessToken())
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(response.expiresIn())
                .build();
        LoginResponse body = new LoginResponse(null, response.expiresIn(), response.user());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(body);
    }

    private ResponseCookie expiredCookie() {
        return ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build();
    }

    private String currentToken(HttpServletRequest request, String authorizationHeader) {
        Object requestToken = request.getAttribute(JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE);
        if (requestToken instanceof String token && !token.isBlank()) {
            return token;
        }
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

}
