package com.flarefitness.backend.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.security.PasswordPolicy;
import com.flarefitness.backend.security.RedisTokenStore;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class ProfileServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private CustomerRepository customerRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthService authService;
    @Mock private EmailOtpService emailOtpService;
    @Mock private PhoneNumberService phoneNumberService;
    @Mock private RedisTokenStore redisTokenStore;
    @Mock private PasswordPolicy passwordPolicy;
    @Mock private IpRateLimitService ipRateLimitService;
    @Mock private AuditLogService auditLogService;
    @Mock private com.flarefitness.backend.service.siem.SecurityEventService securityEventService;

    private ProfileService profileService;

    @BeforeEach
    void setUp() {
        profileService = new ProfileService(
                userRepository,
                customerRepository,
                passwordEncoder,
                authService,
                emailOtpService,
                phoneNumberService,
                redisTokenStore,
                passwordPolicy,
                ipRateLimitService,
                auditLogService,
                securityEventService);
    }

    @Test
    void profileUpdateDoesNotAttachACustomerByMatchingFullName() {
        User user = new User();
        user.setId("user-a");
        user.setUsername("customer-a");
        user.setRole("Khach hang");
        user.setHoTen("Nguyen Van A");
        user.setEmail("a@example.test");
        when(userRepository.findByUsernameIgnoreCaseForUpdate("customer-a")).thenReturn(Optional.of(user));
        when(phoneNumberService.requireAvailable("0935250037", "user-a")).thenReturn("0935250037");
        when(customerRepository.findUniqueActiveByUserId("user-a")).thenReturn(Optional.empty());

        profileService.updateProfile(
                "customer-a",
                new UpdateProfileRequest("Nguyen Van A", "a@example.test", "0935250037", null));

        verify(customerRepository).save(any());
        verify(customerRepository, never()).findActiveByEmailIgnoreCase(any());
        verify(auditLogService).success("ACCOUNT_PROFILE_UPDATE", "user-a", "user-a", "USER", "user-a");
    }

    @Test void sensitiveAttemptPrecedesPasswordMutationAndCompletedAction() {
        User user = new User(); user.setId("user-a"); user.setUsername("customer-a"); user.setPassword("old-hash");
        when(userRepository.findByUsernameIgnoreCaseForUpdate("customer-a")).thenReturn(Optional.of(user));
        when(securityEventService.isPostLoginEnabled()).thenReturn(true);
        when(authService.passwordMatches("current", user)).thenReturn(true);
        when(passwordEncoder.encode("NewPassword1!")).thenReturn("new-hash");
        profileService.changePassword("customer-a", new com.flarefitness.backend.dto.profile.ChangePasswordRequest(
                "current", "NewPassword1!", "NewPassword1!"));
        var order = org.mockito.Mockito.inOrder(securityEventService, userRepository, redisTokenStore);
        order.verify(securityEventService).recordSensitiveActionAttempt("PASSWORD_CHANGE", "user-a");
        order.verify(userRepository).save(user);
        order.verify(redisTokenStore).revokeAll("customer-a");
        order.verify(securityEventService).recordDomainAction("PASSWORD_CHANGE", "user-a", "user-a");
    }

    @Test void failedPasswordValidationStillObservesAttemptWithoutACompletedAction() {
        User user = new User(); user.setId("user-a"); user.setUsername("customer-a");
        when(userRepository.findByUsernameIgnoreCaseForUpdate("customer-a")).thenReturn(Optional.of(user));
        when(securityEventService.isPostLoginEnabled()).thenReturn(true);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> profileService.changePassword("customer-a",
                new com.flarefitness.backend.dto.profile.ChangePasswordRequest("current", "new", "different")))
                .isInstanceOf(com.flarefitness.backend.exception.BadRequestException.class);
        verify(securityEventService).recordSensitiveActionAttempt("PASSWORD_CHANGE", "user-a");
        verify(userRepository, never()).save(any());
        verify(securityEventService, never()).recordDomainAction(any(), any(), any());
    }

    @Test void enabledPolicyPreventsPasswordMutationThroughLegacyEndpointRegardlessOfRisk() {
        User user = new User(); user.setId("user-a"); user.setUsername("customer-a");
        when(userRepository.findByUsernameIgnoreCaseForUpdate("customer-a")).thenReturn(Optional.of(user));
        profileService = new ProfileService(userRepository, customerRepository, passwordEncoder, authService,
                emailOtpService, phoneNumberService, redisTokenStore, passwordPolicy, ipRateLimitService,
                auditLogService, securityEventService, new SensitiveActionPolicy(true, "user-a"));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> profileService.changePassword("customer-a",
                new com.flarefitness.backend.dto.profile.ChangePasswordRequest("current", "NewPassword1!", "NewPassword1!")))
                .isInstanceOf(com.flarefitness.backend.exception.ActionConfirmationRequiredException.class);
        verify(userRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
        verify(redisTokenStore, never()).revokeAll(any());
    }

    @Test void destinationEmailOtpCannotReplaceCurrentAccountActionConfirmation() {
        User user = new User(); user.setId("user-a"); user.setUsername("customer-a");
        user.setEmail("owner@example.test");
        when(userRepository.findByUsernameIgnoreCaseForUpdate("customer-a")).thenReturn(Optional.of(user));
        profileService = new ProfileService(userRepository, customerRepository, passwordEncoder, authService,
                emailOtpService, phoneNumberService, redisTokenStore, passwordPolicy, ipRateLimitService,
                auditLogService, securityEventService, new SensitiveActionPolicy(true, "user-a"));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> profileService.updateProfile("customer-a",
                new UpdateProfileRequest("Owner", "attacker@example.test", "", "123456")))
                .isInstanceOf(com.flarefitness.backend.exception.ActionConfirmationRequiredException.class);
        verify(userRepository, never()).save(any());
        verify(emailOtpService, never()).verifyOtp(any(), any(), any());
    }
}
