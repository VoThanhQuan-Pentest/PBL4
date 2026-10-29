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
    @Mock private com.flarefitness.backend.service.siem.SecurityEventService securityEventService;

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
                auditLogService,
                securityEventService);
    }

    @Test
    void recoveryProofAuditDoesNotTurnItsOwnerIntoAnAuthenticatedActor() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        when(passwordResetTokenStore.issue(owner)).thenReturn("owned-opaque-grant");
        var response = authService.verifyForgotPasswordOtp(recoveryRequest());
        org.assertj.core.api.Assertions.assertThat(response.resetToken()).isEqualTo("owned-opaque-grant");
        verify(emailOtpService).verifyRecoveryOtp(owner, "123456");
        verify(auditLogService).success("AUTH_PASSWORD_RESET_EMAIL_OTP_VERIFIED", null, owner.getId(), "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(securityEventService, redisTokenStore, jwtTokenService);
    }

    @Test
    void missingRecoveryOwnerHasAnUnassociatedRejectionAndNoGrant() {
        when(userRepository.findByEmailIgnoreCaseForUpdate("owned@example.test")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest()))
                .isInstanceOf(BadRequestException.class).hasMessage("Ma OTP khong dung hoac da het han.");
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(emailOtpService, passwordResetTokenStore, securityEventService);
    }

    @Test
    void invalidRecoveryProofPreservesItsExceptionAndDoesNotIssueAGrant() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        var rejected = new BadRequestException("owned rejection");
        doThrow(rejected).when(emailOtpService).verifyRecoveryOtp(owner, "123456");
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest())).isSameAs(rejected);
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(passwordResetTokenStore, securityEventService);
    }

    @Test
    void recoveryVerificationRateLimitRetainsItsOutcomeWithoutClaimingExpiryOrReplay() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        var rejected = new TooManyRequestsException("owned budget");
        doThrow(rejected).when(emailOtpService).verifyRecoveryOtp(owner, "123456");
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest())).isSameAs(rejected);
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_RATE_LIMITED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(passwordResetTokenStore, securityEventService);
    }

    @Test
    void grantStorageFailureIsAnErrorRatherThanASuccessfulRecoveryProof() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        var unavailable = new IllegalStateException("owned storage unavailable");
        when(passwordResetTokenStore.issue(owner)).thenThrow(unavailable);
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest())).isSameAs(unavailable);
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(securityEventService);
    }

    @Test
    void unavailableRecoveryAuditCannotReplaceTheOriginalRejection() {
        when(userRepository.findByEmailIgnoreCaseForUpdate("owned@example.test")).thenReturn(Optional.empty());
        doThrow(new IllegalStateException("owned sink unavailable")).when(auditLogService)
                .failure("AUTH_PASSWORD_RESET_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest()))
                .isInstanceOf(BadRequestException.class).hasMessage("Ma OTP khong dung hoac da het han.");
        org.mockito.Mockito.verifyNoInteractions(passwordResetTokenStore, securityEventService);
    }

    private User recoveryOwner() {
        User owner = new User(); owner.setId("owned-recovery-account"); owner.setEmail("owned@example.test");
        return owner;
    }

    @Test
    void registrationIssuanceAuditDoesNotAttributeAnUnverifiedAccount() {
        authService.sendRegisterOtp(new OtpRequest("owned-register", "owned@example.test", "0935250037"), "127.0.0.1");
        verify(emailOtpService).sendOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test");
        verify(auditLogService).success("AUTH_REGISTER_EMAIL_OTP_ISSUED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(securityEventService, jwtTokenService, redisTokenStore);
    }

    @Test
    void duplicateRegistrationRequestIsRejectedWithoutClaimingInvalidOtp() {
        when(userRepository.existsByUsernameIgnoreCase("owned-register")).thenReturn(true);
        assertThatThrownBy(() -> authService.sendRegisterOtp(
                new OtpRequest("owned-register", "owned@example.test", "0935250037"), "127.0.0.1"))
                .isInstanceOf(BadRequestException.class).hasMessage("Ten dang nhap da ton tai.");
        verify(auditLogService).failure("AUTH_REGISTER_OTP_REQUEST_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoInteractions(emailOtpService, securityEventService);
    }

    @Test
    void registrationDeliveryFailurePreservesItsExceptionAndHasNoIssuedSuccess() {
        var unavailable = new IllegalStateException("owned mail transport");
        doThrow(unavailable).when(emailOtpService).sendOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test");
        assertThatThrownBy(() -> authService.sendRegisterOtp(
                new OtpRequest("owned-register", "owned@example.test", "0935250037"), "127.0.0.1")).isSameAs(unavailable);
        verify(auditLogService).failure("AUTH_REGISTER_OTP_REQUEST_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
    }

    @Test
    void registrationSendRateLimitDoesNotDeliverOtp() {
        var rejected = new TooManyRequestsException("owned budget");
        doThrow(rejected).when(ipRateLimitService).assertOtpSendAllowed(
                EmailOtpService.PURPOSE_REGISTER, "owned@example.test", "127.0.0.1");
        assertThatThrownBy(() -> authService.sendRegisterOtp(
                new OtpRequest("owned-register", "owned@example.test", "0935250037"), "127.0.0.1")).isSameAs(rejected);
        verify(auditLogService).failure("AUTH_REGISTER_OTP_REQUEST_RATE_LIMITED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoInteractions(emailOtpService);
    }

    @Test
    void invalidRegistrationProofIsAGenericRegistrationRejection() {
        var rejected = new BadRequestException("owned proof rejection");
        doThrow(rejected).when(emailOtpService).verifyOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test", "123456");
        assertThatThrownBy(() -> authService.register(registrationRequest())).isSameAs(rejected);
        verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        verify(userRepository, never()).save(any());
        org.mockito.Mockito.verifyNoInteractions(jwtTokenService, redisTokenStore, securityEventService);
    }

    @Test
    void registrationProofBudgetPreservesTheRateLimitException() {
        var rejected = new TooManyRequestsException("owned verification budget");
        doThrow(rejected).when(emailOtpService).verifyOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test", "123456");
        assertThatThrownBy(() -> authService.register(registrationRequest())).isSameAs(rejected);
        verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_RATE_LIMITED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoInteractions(jwtTokenService, redisTokenStore, securityEventService);
    }

    @Test
    void postProofSessionFailureDoesNotClaimCompletedRegistrationFactor() {
        var unavailable = new IllegalStateException("owned token storage");
        when(jwtTokenService.generateToken(any())).thenThrow(unavailable);
        assertThatThrownBy(() -> authService.register(registrationRequest())).isSameAs(unavailable);
        verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        verify(auditLogService, never()).success(eq("AUTH_REGISTER_EMAIL_OTP_VERIFIED"), any(), any(), any(), any());
    }

    @Test
    void registrationSuccessAuditsOnlyPersistedOpaqueIdentityAfterIssuingTheSession() {
        when(jwtTokenService.generateToken(any())).thenReturn("owned-session");
        var response = authService.register(registrationRequest());
        org.assertj.core.api.Assertions.assertThat(response.accessToken()).isEqualTo("owned-session");
        var order = org.mockito.Mockito.inOrder(emailOtpService, redisTokenStore, auditLogService);
        order.verify(emailOtpService).verifyOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test", "123456");
        order.verify(auditLogService).success("ACCOUNT_REGISTER", response.user().id(), response.user().id(), "USER", response.user().id());
        order.verify(redisTokenStore).save("owned-session", "owned-register", 0L);
        order.verify(auditLogService).success("AUTH_REGISTER_EMAIL_OTP_VERIFIED", null, response.user().id(), "AUTH_FACTOR", "EMAIL_OTP");
        verify(securityEventService).recordDomainAction("ACCOUNT_REGISTER", response.user().id(), response.user().id());
        org.mockito.Mockito.verifyNoMoreInteractions(securityEventService);
    }

    @Test
    void registrationAuditFailureCannotReplaceAnExistingRejection() {
        when(userRepository.existsByUsernameIgnoreCase("owned-register")).thenReturn(true);
        doThrow(new IllegalStateException("owned sink")).when(auditLogService)
                .failure("AUTH_REGISTER_ATTEMPT_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        assertThatThrownBy(() -> authService.register(registrationRequest()))
                .isInstanceOf(BadRequestException.class).hasMessage("Ten dang nhap da ton tai.");
        org.mockito.Mockito.verifyNoInteractions(emailOtpService, jwtTokenService, redisTokenStore, securityEventService);
    }

    private com.flarefitness.backend.dto.auth.RegisterRequest registrationRequest() {
        return new com.flarefitness.backend.dto.auth.RegisterRequest("owned-register", "Owned fixture", "owned@example.test",
                "0935250037", "Owned registration password", "Owned registration password", "123456");
    }

    @Test
    void aPostProofPhoneConflictIsNotLabelledAnInvalidEmailFactor() {
        var rejected = new BadRequestException("owned phone collision");
        when(phoneNumberService.requireAvailable("0935250037", null)).thenReturn("0935250037").thenThrow(rejected);
        assertThatThrownBy(() -> authService.register(registrationRequest())).isSameAs(rejected);
        verify(emailOtpService).verifyOtp(EmailOtpService.PURPOSE_REGISTER, "owned@example.test", "123456");
        verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        verify(userRepository, never()).save(any());
        org.mockito.Mockito.verifyNoInteractions(jwtTokenService, redisTokenStore, securityEventService);
    }

    @Test
    void newRegistrationSuccessAuditFailureCannotReplaceTheIssuedSession() {
        when(jwtTokenService.generateToken(any())).thenReturn("owned-session");
        org.mockito.Mockito.doAnswer(call -> {
            if ("AUTH_REGISTER_EMAIL_OTP_VERIFIED".equals(call.getArgument(0))) {
                throw new IllegalStateException("owned sink");
            }
            return null;
        }).when(auditLogService).success(any(), any(), any(), any(), any());
        org.assertj.core.api.Assertions.assertThat(authService.register(registrationRequest()).accessToken()).isEqualTo("owned-session");
        verify(redisTokenStore).save("owned-session", "owned-register", 0L);
    }

    @Test
    void registrationTransactionFailureProducesOneUnassociatedError() {
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        try {
            authService.register(registrationRequest());
            var hooks = org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations();
            hooks.forEach(h -> h.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_UNKNOWN));
            verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void registrationRollbackDoesNotDuplicateAnAlreadyAuditedRejection() {
        when(userRepository.existsByUsernameIgnoreCase("owned-register")).thenReturn(true);
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        try {
            assertThatThrownBy(() -> authService.register(registrationRequest())).isInstanceOf(BadRequestException.class);
            org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations()
                    .forEach(h -> h.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_ROLLED_BACK));
            verify(auditLogService).failure("AUTH_REGISTER_ATTEMPT_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
            org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void unavailableRecoveryAuditCannotReplaceTheIssuedGrant() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        when(passwordResetTokenStore.issue(owner)).thenReturn("owned-opaque-grant");
        doThrow(new IllegalStateException("owned sink unavailable")).when(auditLogService)
                .success("AUTH_PASSWORD_RESET_EMAIL_OTP_VERIFIED", null, owner.getId(), "AUTH_FACTOR", "EMAIL_OTP");
        org.assertj.core.api.Assertions.assertThat(authService.verifyForgotPasswordOtp(recoveryRequest()).resetToken())
                .isEqualTo("owned-opaque-grant");
        org.mockito.Mockito.verifyNoInteractions(securityEventService, redisTokenStore, jwtTokenService);
    }

    @Test
    void recoveryLookupFailureIsAuditedWithoutCallingProofOrGrantStorage() {
        var unavailable = new IllegalStateException("owned lookup unavailable");
        when(userRepository.findByEmailIgnoreCaseForUpdate("owned@example.test")).thenThrow(unavailable);
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest())).isSameAs(unavailable);
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(emailOtpService, passwordResetTokenStore, securityEventService);
    }

    @Test
    void recoveryProofInfrastructureFailureCannotIssueAGrant() {
        User owner = recoveryOwner();
        when(userRepository.findByEmailIgnoreCaseForUpdate(owner.getEmail())).thenReturn(Optional.of(owner));
        var unavailable = new IllegalStateException("owned verification unavailable");
        doThrow(unavailable).when(emailOtpService).verifyRecoveryOtp(owner, "123456");
        assertThatThrownBy(() -> authService.verifyForgotPasswordOtp(recoveryRequest())).isSameAs(unavailable);
        verify(auditLogService).failure("AUTH_PASSWORD_RESET_EMAIL_OTP_ERROR", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        org.mockito.Mockito.verifyNoMoreInteractions(auditLogService);
        org.mockito.Mockito.verifyNoInteractions(passwordResetTokenStore, securityEventService);
    }

    private com.flarefitness.backend.dto.auth.ForgotPasswordOtpVerifyRequest recoveryRequest() {
        return new com.flarefitness.backend.dto.auth.ForgotPasswordOtpVerifyRequest("owned@example.test", "123456");
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
        when(userRepository.findByEmailIgnoreCaseForUpdate("legacy@example.test")).thenReturn(Optional.of(user));
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
        verify(emailOtpService, never()).sendRecoveryOtp(any());
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
                .sendRecoveryOtp(user);

        authService.sendForgotPasswordOtp(new OtpRequest(null, "MEMBER@example.test", null), "127.0.0.1");

        verify(emailOtpService).sendRecoveryOtp(user);
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
                .sendRecoveryOtp(user);

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
        when(userRepository.upgradePasswordHash("user-1", "$2a$10$stored-hash", 0L, "$2a$12$new-hash")).thenReturn(1);
        when(jwtTokenService.generateToken(any())).thenReturn("test-token");
        when(jwtTokenService.getExpirationSeconds()).thenReturn(3600L);

        authService.login(new LoginRequest("rehash-user", "ValidPassword1!"), "127.0.0.1");

        org.assertj.core.api.Assertions.assertThat(user.getPassword()).isEqualTo("$2a$12$new-hash");
        verify(userRepository).upgradePasswordHash("user-1", "$2a$10$stored-hash", 0L, "$2a$12$new-hash");
        verify(userRepository, never()).save(any());
        verify(ipRateLimitService).recordSuccessfulLogin("127.0.0.1", "rehash-user");
        verify(auditLogService).success("AUTH_LOGIN", "user-1", "user-1", "USER", "user-1");
    }

    @Test
    void staleLoginHashMigrationCannotOverwriteAConcurrentPasswordReset() {
        User user = new User(); user.setId("old-user"); user.setUsername("old-user");
        user.setPassword("$2a$10$old-hash");
        when(userRepository.findByUsernameIgnoreCase("old-user")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("ValidPassword1!", "$2a$10$old-hash")).thenReturn(true);
        when(passwordEncoder.upgradeEncoding("$2a$10$old-hash")).thenReturn(true);
        when(passwordEncoder.encode("ValidPassword1!")).thenReturn("$2a$12$replacement");
        // The compare-and-set returns zero after the account security epoch changed.
        when(userRepository.upgradePasswordHash("old-user", "$2a$10$old-hash", 0L, "$2a$12$replacement")).thenReturn(0);
        assertThatThrownBy(() -> authService.login(new LoginRequest("old-user", "ValidPassword1!"), "127.0.0.1"))
                .isInstanceOf(UnauthorizedException.class);
        verify(userRepository, never()).save(any());
        verify(jwtTokenService, never()).generateToken(any());
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
