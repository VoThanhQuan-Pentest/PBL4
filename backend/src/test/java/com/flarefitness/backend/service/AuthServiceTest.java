package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.dto.auth.ForgotPasswordRequest;
import com.flarefitness.backend.dto.auth.OtpRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.TooManyRequestsException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.security.PasswordPolicy;
import com.flarefitness.backend.security.PasswordResetTokenStore;
import com.flarefitness.backend.security.RedisTokenStore;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private CustomerRepository customerRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenService jwtTokenService;
    @Mock private RedisTokenStore redisTokenStore;
    @Mock private IpRateLimitService ipRateLimitService;
    @Mock private EmailOtpService emailOtpService;
    @Mock private PhoneNumberService phoneNumberService;
    @Mock private PasswordResetTokenStore passwordResetTokenStore;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private AuditLogService auditLogService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository,
                customerRepository,
                passwordEncoder,
                jwtTokenService,
                redisTokenStore,
                ipRateLimitService,
                emailOtpService,
                phoneNumberService,
                passwordResetTokenStore,
                passwordPolicy,
                auditLogService);
    }

    @Test
    void loginRejectsDisabledAccountEvenWhenPasswordMatches() {
        User user = new User();
        user.setId("user-1");
        user.setUsername("disabled-user");
        user.setPassword("$2a$10$stored-hash");
        user.setRole("Khach hang");
        user.setHoTen("Disabled User");
        user.setStatus("Ngung hoat dong");
        user.setDeleted(false);
        when(userRepository.findByUsernameIgnoreCase("disabled-user")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("ValidPassword1!", user.getPassword())).thenReturn(true);

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("disabled-user", "ValidPassword1!"),
                "127.0.0.1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Sai ten dang nhap");

        verify(jwtTokenService, never()).generateToken(any());
        verify(ipRateLimitService).assertLoginAllowed("127.0.0.1", "disabled-user");
    }

    @Test
    void loginPerformsFixedDummyBcryptWorkBeforeRejectingAnUnknownUser() {
        when(userRepository.findByUsernameIgnoreCase("missing-user")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("missing-user", "Any password value"),
                "127.0.0.1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Sai ten dang nhap");

        verify(passwordEncoder).matches(
                AuthService.DUMMY_LOGIN_PASSWORD,
                AuthService.DUMMY_LOGIN_PASSWORD_HASH);
        verify(ipRateLimitService).assertLoginAllowed("127.0.0.1", "missing-user");
        verify(auditLogService).failure("AUTH_LOGIN", null, null, "USER", null);
    }

    @Test
    void loginRejectsLegacyPlaintextPasswordsWithoutMigratingThem() {
        User user = new User();
        user.setId("user-1");
        user.setUsername("legacy-user");
        user.setPassword("plain-text-password");
        user.setRole("Khach hang");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        when(userRepository.findByUsernameIgnoreCase("legacy-user")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(
                new LoginRequest("legacy-user", "plain-text-password"),
                "127.0.0.1"))
                .isInstanceOf(UnauthorizedException.class);

        verify(passwordEncoder, never()).matches(any(), any());
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(user);
        verify(ipRateLimitService).assertLoginAllowed("127.0.0.1", "legacy-user");
    }

    @Test
    void passwordResetClosesTheLegacyCredentialAuditRecord() {
        User user = new User();
        user.setId("legacy-user");
        user.setUsername("legacy-user");
        user.setEmail("legacy@example.test");
        when(userRepository.findByEmailIgnoreCase("legacy@example.test")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("A long replacement password")).thenReturn("{bcrypt-sha256}$2a$12$replacement");

        authService.forgotPassword(new ForgotPasswordRequest(
                "legacy@example.test",
                "reset-token",
                "A long replacement password",
                "A long replacement password"));

        verify(userRepository).markPasswordResetCompleted("legacy-user");
        verify(redisTokenStore).revokeAll("legacy-user");
    }

    @Test
    void forgotPasswordOtpUsesTheSameOutwardFlowForAnUnknownEmail() {
        when(userRepository.findByEmailIgnoreCase("missing@example.test")).thenReturn(Optional.empty());

        authService.sendForgotPasswordOtp(new OtpRequest(null, "missing@example.test", null), "127.0.0.1");

        verify(ipRateLimitService).assertOtpSendAllowed(
                EmailOtpService.PURPOSE_FORGOT_PASSWORD,
                "missing@example.test",
                "127.0.0.1");
        verify(emailOtpService, never()).sendOtp(any(), any());
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, null, "USER", null);
    }

    @Test
    void forgotPasswordOtpHidesDeliveryAndConfigurationFailuresForExistingAccounts() {
        User user = new User();
        user.setId("user-1");
        user.setEmail("member@example.test");
        when(userRepository.findByEmailIgnoreCase("member@example.test")).thenReturn(Optional.of(user));
        doThrow(new BadRequestException("SMTP credentials are not configured"))
                .when(emailOtpService)
                .sendOtp(EmailOtpService.PURPOSE_FORGOT_PASSWORD, "member@example.test");

        authService.sendForgotPasswordOtp(new OtpRequest(null, "MEMBER@example.test", null), "127.0.0.1");

        verify(emailOtpService).sendOtp(EmailOtpService.PURPOSE_FORGOT_PASSWORD, "member@example.test");
        verify(auditLogService).failure(
                "AUTH_PASSWORD_RESET_OTP_REQUEST",
                null,
                "user-1",
                "USER",
                "user-1");
    }

    @Test
    void forgotPasswordOtpDoesNotExposeAccountSpecificDeliveryCooldowns() {
        User user = new User();
        user.setId("user-1");
        when(userRepository.findByEmailIgnoreCase("member@example.test")).thenReturn(Optional.of(user));
        doThrow(new TooManyRequestsException("cooldown"))
                .when(emailOtpService)
                .sendOtp(eq(EmailOtpService.PURPOSE_FORGOT_PASSWORD), eq("member@example.test"));

        authService.sendForgotPasswordOtp(new OtpRequest(null, "member@example.test", null), "127.0.0.1");

        verify(auditLogService).failure(
                "AUTH_PASSWORD_RESET_OTP_REQUEST",
                null,
                "user-1",
                "USER",
                "user-1");
    }

    @Test
    void forgotPasswordOtpPreservesPreLookupRateLimitErrors() {
        doThrow(new TooManyRequestsException("rate limited"))
                .when(ipRateLimitService)
                .assertOtpSendAllowed(
                        EmailOtpService.PURPOSE_FORGOT_PASSWORD,
                        "member@example.test",
                        "127.0.0.1");

        assertThatThrownBy(() -> authService.sendForgotPasswordOtp(
                new OtpRequest(null, "member@example.test", null), "127.0.0.1"))
                .isInstanceOf(TooManyRequestsException.class)
                .hasMessageContaining("rate limited");

        verify(userRepository, never()).findByEmailIgnoreCase(any());
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, null, "USER", null);
    }

    @Test
    void loginUpgradesAnOlderBcryptHashAfterSuccessfulAuthentication() {
        User user = new User();
        user.setId("user-1");
        user.setUsername("rehash-user");
        user.setPassword("$2a$10$stored-hash");
        user.setRole("Khach hang");
        user.setHoTen("Rehash User");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        when(userRepository.findByUsernameIgnoreCase("rehash-user")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("ValidPassword1!", user.getPassword())).thenReturn(true);
        when(passwordEncoder.upgradeEncoding(user.getPassword())).thenReturn(true);
        when(passwordEncoder.encode("ValidPassword1!")).thenReturn("$2a$12$new-hash");
        when(jwtTokenService.generateToken(any())).thenReturn("test-token");
        when(jwtTokenService.getExpirationSeconds()).thenReturn(3600L);

        authService.login(new LoginRequest("rehash-user", "ValidPassword1!"), "127.0.0.1");

        org.assertj.core.api.Assertions.assertThat(user.getPassword()).isEqualTo("$2a$12$new-hash");
        verify(userRepository).save(user);
        verify(ipRateLimitService).recordSuccessfulLogin("127.0.0.1", "rehash-user");
        verify(auditLogService).success("AUTH_LOGIN", "user-1", "user-1", "USER", "user-1");
    }

    @Test
    void customerLinkingNeverFallsBackToSameFullName() {
        User user = new User();
        user.setId("user-a");
        user.setHoTen("Nguyen Van A");
        user.setEmail("a@example.test");
        when(customerRepository.findUniqueActiveByUserId("user-a")).thenReturn(Optional.empty());

        org.assertj.core.api.Assertions.assertThat(authService.findLinkedCustomer(user)).isEmpty();
        verify(customerRepository, never()).findActiveByEmailIgnoreCase(any());
    }

    @Test
    void customerLinkingDoesNotReadMutableEmailAtLogin() {
        User user = new User();
        user.setId("user-a");
        user.setEmail("shared@example.test");
        when(customerRepository.findUniqueActiveByUserId("user-a")).thenReturn(Optional.empty());

        org.assertj.core.api.Assertions.assertThat(authService.findLinkedCustomer(user)).isEmpty();
        verify(customerRepository, never()).findActiveByEmailIgnoreCase(any());
    }
}
