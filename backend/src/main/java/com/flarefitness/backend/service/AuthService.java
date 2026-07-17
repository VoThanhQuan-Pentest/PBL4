package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.auth.CurrentUserResponse;
import com.flarefitness.backend.dto.auth.ForgotPasswordOtpVerifyRequest;
import com.flarefitness.backend.dto.auth.ForgotPasswordRequest;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.dto.auth.LoginResponse;
import com.flarefitness.backend.dto.auth.OtpRequest;
import com.flarefitness.backend.dto.auth.PasswordResetVerificationResponse;
import com.flarefitness.backend.dto.auth.RegisterRequest;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.security.PasswordResetTokenStore;
import com.flarefitness.backend.security.PasswordPolicy;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.exception.TooManyRequestsException;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final String CUSTOMER_ROLE = "Khach hang";
    /**
     * A fixed BCrypt-12 comparison for usernames that do not exist.  Keeping
     * both values fixed makes the work independent of attacker-controlled
     * input and prevents the user lookup from becoming a cheap timing oracle.
     * The value is deliberately not an account credential.
     */
    static final String DUMMY_LOGIN_PASSWORD = "flare-fitness-login-timing-padding";
    static final String DUMMY_LOGIN_PASSWORD_HASH = "{bcrypt-sha256}$2a$12$ym0sFUYu4s/uNxj6RyTGxeJAiDHwTivYWPyJBv2J6GxV8fPwgzT92";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final RedisTokenStore redisTokenStore;
    private final IpRateLimitService ipRateLimitService;
    private final EmailOtpService emailOtpService;
    private final PhoneNumberService phoneNumberService;
    private final PasswordResetTokenStore passwordResetTokenStore;
    private final PasswordPolicy passwordPolicy;
    private final AuditLogService auditLogService;

    public AuthService(
            UserRepository userRepository,
            CustomerRepository customerRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService,
            RedisTokenStore redisTokenStore,
            IpRateLimitService ipRateLimitService,
            EmailOtpService emailOtpService,
            PhoneNumberService phoneNumberService,
            PasswordResetTokenStore passwordResetTokenStore,
            PasswordPolicy passwordPolicy,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.redisTokenStore = redisTokenStore;
        this.ipRateLimitService = ipRateLimitService;
        this.emailOtpService = emailOtpService;
        this.phoneNumberService = phoneNumberService;
        this.passwordResetTokenStore = passwordResetTokenStore;
        this.passwordPolicy = passwordPolicy;
        this.auditLogService = auditLogService;
    }

    public LoginResponse login(LoginRequest request, String ipAddress) {
        String username = normalizeUsername(request.username());
        try {
            ipRateLimitService.assertLoginAllowed(ipAddress, username);
        } catch (TooManyRequestsException exception) {
            auditLogService.failure("AUTH_LOGIN", null, null, "USER", null);
            throw exception;
        }

        Optional<User> foundUser = userRepository.findByUsernameIgnoreCase(username);
        if (foundUser.isEmpty()) {
            consumeDummyLoginPasswordWork();
            throw invalidCredentials(null);
        }
        User user = foundUser.get();

        if (!passwordMatches(request.password(), user)) {
            throw invalidCredentials(user.getId());
        }

        if (!new CurrentUserPrincipal(user).isEnabled()) {
            throw invalidCredentials(user.getId());
        }

        ipRateLimitService.recordSuccessfulLogin(ipAddress, username);
        LoginResponse response = issueLoginResponse(user);
        auditLogService.success("AUTH_LOGIN", user.getId(), user.getId(), "USER", user.getId());
        return response;
    }

    @Transactional
    public LoginResponse register(RegisterRequest request) {
        validateRegisterRequest(request);
        emailOtpService.verifyOtp(EmailOtpService.PURPOSE_REGISTER, request.email(), request.otpCode());
        String phoneNumber = phoneNumberService.requireAvailable(request.sdt(), null);

        User user = new User();
        user.setId(generateUserId(CUSTOMER_ROLE));
        user.setUsername(request.username().trim());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(CUSTOMER_ROLE);
        user.setHoTen(request.hoTen().trim());
        user.setEmail(request.email().trim());
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());

        userRepository.save(user);

        Customer customer = findOrCreateCustomerForUser(user);
        customer.setUserId(user.getId());
        customer.setTenKhach(user.getHoTen());
        customer.setEmail(user.getEmail());
        customer.setSdt(phoneNumber);
        customer.setKenh(isBlank(customer.getKenh()) ? "Website" : customer.getKenh());
        customer.setNhan(isBlank(customer.getNhan()) ? "Moi" : customer.getNhan());
        customer.setTongChiTieu(customer.getTongChiTieu() == null ? BigDecimal.ZERO : customer.getTongChiTieu());
        if (customer.getCreatedAt() == null) {
            customer.setCreatedAt(LocalDateTime.now());
        }
        customer.setUpdatedAt(LocalDateTime.now());

        customerRepository.save(customer);
        auditLogService.success("ACCOUNT_REGISTER", user.getId(), user.getId(), "USER", user.getId());
        return issueLoginResponse(user);
    }

    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new BadRequestException("Xac nhan mat khau khong khop.");
        }
        passwordPolicy.validateNewPassword(request.newPassword());

        String requestEmail = request.email().trim();
        User user = userRepository.findByEmailIgnoreCase(requestEmail)
                .orElseThrow(() -> new BadRequestException("Thong tin khoi phuc khong dung."));
        passwordResetTokenStore.consume(requestEmail, request.resetToken());
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        userRepository.markPasswordResetCompleted(user.getId());
        redisTokenStore.revokeAll(user.getUsername());
        auditLogService.success("ACCOUNT_PASSWORD_RESET", user.getId(), user.getId(), "USER", user.getId());
    }

    public void sendRegisterOtp(OtpRequest request, String ipAddress) {
        String email = request.email().trim();
        String username = request.username() == null ? "" : request.username().trim();
        if (!username.isBlank() && userRepository.existsByUsernameIgnoreCase(username)) {
            throw new BadRequestException("Ten dang nhap da ton tai.");
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new BadRequestException("Email da duoc su dung.");
        }
        phoneNumberService.requireAvailable(request.sdt(), null);
        ipRateLimitService.assertOtpSendAllowed(EmailOtpService.PURPOSE_REGISTER, email, ipAddress);
        emailOtpService.sendOtp(EmailOtpService.PURPOSE_REGISTER, email);
    }

    public void sendForgotPasswordOtp(OtpRequest request, String ipAddress) {
        String email = normalizeEmail(request.email());
        try {
            ipRateLimitService.assertOtpSendAllowed(EmailOtpService.PURPOSE_FORGOT_PASSWORD, email, ipAddress);
        } catch (TooManyRequestsException exception) {
            auditLogService.failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, null, "USER", null);
            throw exception;
        }

        Optional<User> foundUser = userRepository.findByEmailIgnoreCase(email);
        if (foundUser.isEmpty()) {
            // The controller deliberately returns the same success response as
            // a real request.  Do not include the submitted e-mail in audit
            // logs because it is user-supplied PII.
            auditLogService.failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, null, "USER", null);
            return;
        }

        User user = foundUser.get();
        try {
            emailOtpService.sendOtp(EmailOtpService.PURPOSE_FORGOT_PASSWORD, email);
            auditLogService.success("AUTH_PASSWORD_RESET_OTP_REQUEST", null, user.getId(), "USER", user.getId());
        } catch (TooManyRequestsException exception) {
            // EmailOtpService's cooldown exists only for real accounts because
            // unknown e-mails never reach it.  Normalise it to the same
            // generic success response to avoid making that state an account
            // enumeration oracle.  The shared IP/e-mail rate limiter above
            // runs before the lookup and remains externally enforceable.
            auditLogService.failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, user.getId(), "USER", user.getId());
            LOGGER.warn("Password-reset OTP delivery cooldown for userId={}", user.getId());
        } catch (RuntimeException exception) {
            // SMTP/configuration/transport failures must not disclose either
            // account existence or operational details to the caller.  Keep
            // only opaque identifiers and an exception type in server logs.
            auditLogService.failure("AUTH_PASSWORD_RESET_OTP_REQUEST", null, user.getId(), "USER", user.getId());
            LOGGER.warn(
                    "Password-reset OTP delivery unavailable for userId={} exceptionType={}",
                    user.getId(),
                    exception.getClass().getSimpleName());
        }
    }

    public PasswordResetVerificationResponse verifyForgotPasswordOtp(ForgotPasswordOtpVerifyRequest request) {
        String email = request.email().trim();
        if (userRepository.findByEmailIgnoreCase(email).isEmpty()) {
            throw new BadRequestException("Ma OTP khong dung hoac da het han.");
        }
        emailOtpService.verifyOtp(EmailOtpService.PURPOSE_FORGOT_PASSWORD, email, request.otpCode());
        return new PasswordResetVerificationResponse(passwordResetTokenStore.issue(email));
    }

    public CurrentUserResponse getCurrentUser(String username) {
        User user = userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new UnauthorizedException("Phien dang nhap khong hop le."));
        return toCurrentUserResponse(user);
    }

    public void logout(String token) {
        redisTokenStore.revoke(token);
    }

    public void logoutAll(String username) {
        redisTokenStore.revokeAll(username);
    }

    public CurrentUserResponse toCurrentUserResponse(User user) {
        Optional<Customer> customer = findLinkedCustomer(user);
        return new CurrentUserResponse(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                user.getHoTen(),
                user.getEmail(),
                customer.map(Customer::getSdt).orElse(null)
        );
    }

    public Optional<Customer> findLinkedCustomer(User user) {
        // Login/profile/order reads must never attach an existing customer by
        // mutable profile data.  Registration is the sole e-mail-proofed
        // migration path and links the record immediately to this immutable id.
        return customerRepository.findUniqueActiveByUserId(user.getId());
    }

    private UnauthorizedException invalidCredentials(String subjectId) {
        auditLogService.failure("AUTH_LOGIN", null, subjectId, "USER", subjectId);
        return new UnauthorizedException("Sai ten dang nhap hoac mat khau.");
    }

    private void consumeDummyLoginPasswordWork() {
        try {
            passwordEncoder.matches(DUMMY_LOGIN_PASSWORD, DUMMY_LOGIN_PASSWORD_HASH);
        } catch (RuntimeException exception) {
            // An encoder implementation must not make a missing account turn
            // into a different outward response.  The configured encoder uses
            // the valid BCrypt-12 value above, so this is only a fail-closed
            // guard for a broken custom implementation.
            LOGGER.warn("Dummy login-password comparison failed exceptionType={}", exception.getClass().getSimpleName());
        }
    }

    boolean passwordMatches(String rawPassword, User user) {
        String storedPassword = user.getPassword();
        if (storedPassword == null || storedPassword.isBlank()) {
            return false;
        }

        if (!isBcryptHash(storedPassword)) {
            return false;
        }

        try {
            if (!passwordEncoder.matches(rawPassword, storedPassword)) {
                return false;
            }
            if (passwordEncoder.upgradeEncoding(storedPassword)) {
                user.setPassword(passwordEncoder.encode(rawPassword));
                userRepository.save(user);
            }
            return true;
        } catch (IllegalArgumentException exception) {
            // A malformed legacy value must never be treated as a usable password.
            return false;
        }
    }

    private LoginResponse issueLoginResponse(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        String token = jwtTokenService.generateToken(principal);
        redisTokenStore.save(token, user.getUsername(), jwtTokenService.getExpirationSeconds());
        return new LoginResponse(token, jwtTokenService.getExpirationSeconds(), toCurrentUserResponse(user));
    }

    private void validateRegisterRequest(RegisterRequest request) {
        if (!request.password().equals(request.confirmPassword())) {
            throw new BadRequestException("Xac nhan mat khau khong khop.");
        }
        passwordPolicy.validateNewPassword(request.password());

        if (userRepository.existsByUsernameIgnoreCase(request.username().trim())) {
            throw new BadRequestException("Ten dang nhap da ton tai.");
        }

        if (userRepository.existsByEmailIgnoreCase(request.email().trim())) {
            throw new BadRequestException("Email da duoc su dung.");
        }
        phoneNumberService.requireAvailable(request.sdt(), null);
    }

    private Customer findOrCreateCustomerForUser(User user) {
        Optional<Customer> existingCustomer = customerRepository.findUniqueActiveByUserId(user.getId());
        if (existingCustomer.isPresent()) {
            return existingCustomer.get();
        }

        // register() reaches this branch only after a successful OTP challenge
        // for the e-mail address, so this is the narrowly scoped verified-data
        // migration path for an older unlinked customer profile.
        Optional<Customer> byEmail = findUniqueSafeCustomerByEmail(user, user.getEmail());
        if (byEmail.isPresent()) {
            return byEmail.get();
        }

        Customer customer = new Customer();
        customer.setId(UUID.randomUUID().toString());
        customer.setTongChiTieu(BigDecimal.ZERO);
        customer.setCreatedAt(LocalDateTime.now());
        customer.setUpdatedAt(LocalDateTime.now());
        return customer;
    }

    private String generateUserId(String role) {
        return getUserIdPrefix(role) + UUID.randomUUID();
    }

    private String getUserIdPrefix(String role) {
        String normalizedRole = role == null ? "" : role.trim().toLowerCase(Locale.ROOT);
        if (normalizedRole.contains("quan") || normalizedRole.contains("admin")) {
            return "user-admin-";
        }
        if (normalizedRole.contains("nhan") || normalizedRole.contains("staff")) {
            return "user-staff-";
        }
        return "user-customer-";
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private Optional<Customer> findUniqueSafeCustomerByEmail(User user, String email) {
        if (isBlank(email)) {
            return Optional.empty();
        }
        List<Customer> matches = customerRepository.findActiveByEmailIgnoreCase(email);
        if (matches.size() != 1) {
            return Optional.empty();
        }
        Customer customer = matches.get(0);
        if (!isBlank(customer.getUserId()) && !customer.getUserId().equals(user.getId())) {
            return Optional.empty();
        }
        return Optional.of(customer);
    }

    private boolean isBcryptHash(String storedPassword) {
        String encodedPassword = storedPassword.startsWith(BcryptSha256PasswordEncoder.PREFIX)
                ? storedPassword.substring(BcryptSha256PasswordEncoder.PREFIX.length())
                : storedPassword;
        return encodedPassword.startsWith("$2a$")
                || encodedPassword.startsWith("$2b$")
                || encodedPassword.startsWith("$2y$");
    }

    private String normalizeUsername(String username) {
        return String.valueOf(username == null ? "" : username).trim();
    }

    private String normalizeEmail(String email) {
        return String.valueOf(email == null ? "" : email).trim().toLowerCase(Locale.ROOT);
    }
}
