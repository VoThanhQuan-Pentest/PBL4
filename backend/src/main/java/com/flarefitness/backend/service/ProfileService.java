package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.auth.CurrentUserResponse;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.PasswordPolicy;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.siem.SecurityEventService;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProfileService {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ProfileService.class);

    private final UserRepository userRepository;
    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;
    private final EmailOtpService emailOtpService;
    private final PhoneNumberService phoneNumberService;
    private final com.flarefitness.backend.security.RedisTokenStore redisTokenStore;
    private final PasswordPolicy passwordPolicy;
    private final IpRateLimitService ipRateLimitService;
    private final AuditLogService auditLogService;
    private final SecurityEventService securityEventService;
    private final SensitiveActionPolicy sensitiveActionPolicy;

    public ProfileService(
            UserRepository userRepository,
            CustomerRepository customerRepository,
            PasswordEncoder passwordEncoder,
            AuthService authService,
            EmailOtpService emailOtpService,
            PhoneNumberService phoneNumberService,
            com.flarefitness.backend.security.RedisTokenStore redisTokenStore,
            PasswordPolicy passwordPolicy,
            IpRateLimitService ipRateLimitService,
            AuditLogService auditLogService,
            SecurityEventService securityEventService
    ) {
        this(userRepository, customerRepository, passwordEncoder, authService, emailOtpService,
                phoneNumberService, redisTokenStore, passwordPolicy, ipRateLimitService,
                auditLogService, securityEventService, new SensitiveActionPolicy(false, ""));
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ProfileService(UserRepository userRepository, CustomerRepository customerRepository,
            PasswordEncoder passwordEncoder, AuthService authService, EmailOtpService emailOtpService,
            PhoneNumberService phoneNumberService,
            com.flarefitness.backend.security.RedisTokenStore redisTokenStore, PasswordPolicy passwordPolicy,
            IpRateLimitService ipRateLimitService, AuditLogService auditLogService,
            SecurityEventService securityEventService, SensitiveActionPolicy sensitiveActionPolicy) {
        this.userRepository = userRepository;
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.authService = authService;
        this.emailOtpService = emailOtpService;
        this.phoneNumberService = phoneNumberService;
        this.redisTokenStore = redisTokenStore;
        this.passwordPolicy = passwordPolicy;
        this.ipRateLimitService = ipRateLimitService;
        this.auditLogService = auditLogService;
        this.securityEventService = securityEventService;
        this.sensitiveActionPolicy = sensitiveActionPolicy;
    }

    public CurrentUserResponse getProfile(String username) {
        User user = loadUser(username);
        return authService.toCurrentUserResponse(user);
    }

    @Transactional
    public CurrentUserResponse updateProfile(String username, UpdateProfileRequest request) {
        User user = loadUserForMutation(username);
        String oldEmail = user.getEmail();
        String requestedEmail = normalizeEmail(request.email());
        boolean emailChanged = !normalizeEmail(oldEmail).equalsIgnoreCase(requestedEmail);
        if (emailChanged) recordSensitiveAttempt("EMAIL_CHANGE", user.getId());
        if (emailChanged && sensitiveActionPolicy.requiresConfirmation(user)) {
            throw new com.flarefitness.backend.exception.ActionConfirmationRequiredException();
        }
        return applyProfileUpdate(user, request, requestedEmail, emailChanged);
    }

    private CurrentUserResponse applyProfileUpdate(User user, UpdateProfileRequest request,
            String requestedEmail, boolean emailChanged) {
        String requestedPhone = isCustomer(user.getRole())
                ? phoneNumberService.requireAvailable(request.sdt(), user.getId())
                : phoneNumberService.normalize(request.sdt());

        if (emailChanged) {
            if (userRepository.existsByEmailIgnoreCaseAndIdNot(requestedEmail, user.getId())) {
                throw new BadRequestException("Email da duoc su dung boi tai khoan khac.");
            }
            emailOtpService.verifyOtp(EmailOtpService.PURPOSE_PROFILE_EMAIL, requestedEmail, request.otpCode());
            user.setEmailVerifiedAt(LocalDateTime.now(java.time.ZoneOffset.UTC));
        }

        user.setHoTen(request.hoTen());
        user.setEmail(requestedEmail);
        userRepository.save(user);

        if (isCustomer(user.getRole())) {
            Customer customer = findOrCreateCustomer(user);
            customer.setUserId(user.getId());
            customer.setTenKhach(request.hoTen());
            customer.setEmail(requestedEmail);
            customer.setSdt(requestedPhone);
            customerRepository.save(customer);
        }

        auditLogService.success("ACCOUNT_PROFILE_UPDATE", user.getId(), user.getId(), "USER", user.getId());
        if (emailChanged) securityEventService.recordDomainAction("EMAIL_CHANGE", user.getId(), user.getId());
        return authService.toCurrentUserResponse(user);
    }

    /** Internal execution path; caller holds the account and challenge locks in one transaction. */
    CurrentUserResponse applyConfirmedEmailChange(User user, UpdateProfileRequest request) {
        if (!sensitiveActionPolicy.requiresConfirmation(user)) {
            throw new com.flarefitness.backend.exception.ConflictException("Chinh sach xac nhan khong con ap dung.");
        }
        String target = normalizeEmail(request.email());
        if (target.equals(normalizeEmail(user.getEmail()))) {
            throw new com.flarefitness.backend.exception.ConflictException("Email tai khoan da thay doi. Hay tao yeu cau moi.");
        }
        return applyProfileUpdate(user, request, target, true);
    }

    String prepareConfirmedPassword(User user, ChangePasswordRequest request) {
        recordSensitiveAttempt("PASSWORD_CHANGE", user.getId());
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new BadRequestException("Mat khau xac nhan khong khop.");
        }
        passwordPolicy.validateNewPassword(request.newPassword());
        if (!authService.passwordMatches(request.currentPassword(), user)) {
            throw new BadRequestException("Mat khau hien tai khong dung.");
        }
        return passwordEncoder.encode(request.newPassword());
    }

    String prepareConfirmedEmail(User user, UpdateProfileRequest request) {
        recordSensitiveAttempt("EMAIL_CHANGE", user.getId());
        String target = normalizeEmail(request.email());
        if (target.equals(normalizeEmail(user.getEmail()))
                || userRepository.existsByEmailIgnoreCaseAndIdNot(target, user.getId())) {
            throw new BadRequestException("Email moi khong hop le hoac da duoc su dung.");
        }
        return isCustomer(user.getRole()) ? phoneNumberService.requireAvailable(request.sdt(), user.getId())
                : phoneNumberService.normalize(request.sdt());
    }

    void applyConfirmedPassword(User user, String encodedPassword) {
        if (!sensitiveActionPolicy.requiresConfirmation(user) || encodedPassword == null || encodedPassword.isBlank()) {
            throw new com.flarefitness.backend.exception.ConflictException("Yeu cau doi mat khau khong con hieu luc.");
        }
        savePasswordAndRevoke(user, encodedPassword);
    }

    public void sendProfileEmailOtp(String username, String email, String ipAddress) {
        User user = loadUser(username);
        String requestedEmail = normalizeEmail(email);
        if (normalizeEmail(user.getEmail()).equalsIgnoreCase(requestedEmail)) {
            throw new BadRequestException("Email moi phai khac email hien tai.");
        }
        if (userRepository.existsByEmailIgnoreCaseAndIdNot(requestedEmail, user.getId())) {
            throw new BadRequestException("Email da duoc su dung boi tai khoan khac.");
        }
        ipRateLimitService.assertOtpSendAllowed(EmailOtpService.PURPOSE_PROFILE_EMAIL, requestedEmail, ipAddress);
        emailOtpService.sendOtp(EmailOtpService.PURPOSE_PROFILE_EMAIL, requestedEmail);
    }

    @Transactional
    public void changePassword(String username, ChangePasswordRequest request) {
        User user = loadUserForMutation(username);
        recordSensitiveAttempt("PASSWORD_CHANGE", user.getId());
        if (sensitiveActionPolicy.requiresConfirmation(user)) {
            throw new com.flarefitness.backend.exception.ActionConfirmationRequiredException();
        }

        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new BadRequestException("Mat khau xac nhan khong khop.");
        }
        passwordPolicy.validateNewPassword(request.newPassword());

        if (!authService.passwordMatches(request.currentPassword(), user)) {
            throw new BadRequestException("Mat khau hien tai khong dung.");
        }

        savePasswordAndRevoke(user, passwordEncoder.encode(request.newPassword()));
    }

    private void savePasswordAndRevoke(User user, String encodedPassword) {
        user.setPassword(encodedPassword);
        user.setAuthVersion((user.getAuthVersion() == null ? 0L : user.getAuthVersion()) + 1L);
        userRepository.save(user);
        redisTokenStore.revokeAll(user.getUsername());
        auditLogService.success("ACCOUNT_PASSWORD_CHANGE", user.getId(), user.getId(), "USER", user.getId());
        securityEventService.recordDomainAction("PASSWORD_CHANGE", user.getId(), user.getId());
    }

    private void recordSensitiveAttempt(String action, String actorId) {
        if (!securityEventService.isPostLoginEnabled()) return;
        try {
            securityEventService.recordSensitiveActionAttempt(action, actorId);
        } catch (RuntimeException exception) {
            LOGGER.warn("Sensitive-action telemetry failed exceptionType={}", exception.getClass().getSimpleName());
        }
    }

    private User loadUser(String username) {
        return userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay nguoi dung."));
    }

    private User loadUserForMutation(String username) {
        return userRepository.findByUsernameIgnoreCaseForUpdate(username)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay nguoi dung."));
    }

    private Customer findOrCreateCustomer(User user) {
        Optional<Customer> existing = customerRepository.findUniqueActiveByUserId(user.getId());

        Customer customer = existing.orElseGet(Customer::new);
        if (customer.getId() == null) {
            customer.setId(UUID.randomUUID().toString());
            customer.setCreatedAt(LocalDateTime.now());
            customer.setKenh("Website");
            customer.setNhan("Moi");
        }
        return customer;
    }

    private boolean isCustomer(String role) {
        return "ROLE_CUSTOMER".equals(com.flarefitness.backend.security.CurrentUserPrincipal.toAuthority(role));
    }

    private String normalizeEmail(String email) {
        return String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
    }

}
