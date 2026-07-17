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
                auditLogService);
    }

    @Test
    void profileUpdateDoesNotAttachACustomerByMatchingFullName() {
        User user = new User();
        user.setId("user-a");
        user.setUsername("customer-a");
        user.setRole("Khach hang");
        user.setHoTen("Nguyen Van A");
        user.setEmail("a@example.test");
        when(userRepository.findByUsernameIgnoreCase("customer-a")).thenReturn(Optional.of(user));
        when(phoneNumberService.requireAvailable("0935250037", "user-a")).thenReturn("0935250037");
        when(customerRepository.findUniqueActiveByUserId("user-a")).thenReturn(Optional.empty());

        profileService.updateProfile(
                "customer-a",
                new UpdateProfileRequest("Nguyen Van A", "a@example.test", "0935250037", null));

        verify(customerRepository).save(any());
        verify(customerRepository, never()).findActiveByEmailIgnoreCase(any());
        verify(auditLogService).success("ACCOUNT_PROFILE_UPDATE", "user-a", "user-a", "USER", "user-a");
    }
}
