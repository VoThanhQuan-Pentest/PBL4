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
import java.text.Normalizer;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProfileService {

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
            AuditLogService auditLogService
    ) {
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
    }

    public CurrentUserResponse getProfile(String username) {
        User user = loadUser(username);
        return authService.toCurrentUserResponse(user);
    }

    @Transactional
    public CurrentUserResponse updateProfile(String username, UpdateProfileRequest request) {
        User user = loadUser(username);
        String oldEmail = user.getEmail();
        String requestedEmail = normalizeEmail(request.email());
        boolean emailChanged = !normalizeEmail(oldEmail).equalsIgnoreCase(requestedEmail);
        String requestedPhone = isCustomer(user.getRole())
                ? phoneNumberService.requireAvailable(request.sdt(), user.getId())
                : phoneNumberService.normalize(request.sdt());

        if (emailChanged) {
            if (userRepository.existsByEmailIgnoreCaseAndIdNot(requestedEmail, user.getId())) {
                throw new BadRequestException("Email da duoc su dung boi tai khoan khac.");
            }
            emailOtpService.verifyOtp(EmailOtpService.PURPOSE_PROFILE_EMAIL, requestedEmail, request.otpCode());
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
        return authService.toCurrentUserResponse(user);
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
        User user = loadUser(username);

        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new BadRequestException("Mat khau xac nhan khong khop.");
        }
        passwordPolicy.validateNewPassword(request.newPassword());

        if (!authService.passwordMatches(request.currentPassword(), user)) {
            throw new BadRequestException("Mat khau hien tai khong dung.");
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        redisTokenStore.revokeAll(user.getUsername());
        auditLogService.success("ACCOUNT_PASSWORD_CHANGE", user.getId(), user.getId(), "USER", user.getId());
    }

    private User loadUser(String username) {
        return userRepository.findByUsernameIgnoreCase(username)
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
        String normalized = stripVietnamese(String.valueOf(role == null ? "" : role)).toLowerCase(Locale.ROOT);
        String raw = String.valueOf(role == null ? "" : role).toLowerCase(Locale.ROOT);
        return normalized.contains("khach")
                || normalized.contains("customer")
                || raw.contains("kh") && raw.contains("ng");
    }

    private String normalizeEmail(String email) {
        return String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
    }

    private String stripVietnamese(String value) {
        return Normalizer.normalize(value, Normalizer.Form.NFD).replaceAll("\\p{M}", "");
    }
}
