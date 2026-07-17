package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.admin.AdminUserRequest;
import com.flarefitness.backend.dto.admin.AdminUserResponse;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.Order;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.math.BigDecimal;
import java.text.Normalizer;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.core.Authentication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminService {

    private static final int LEGACY_LIST_LIMIT = 100;
    private static final String ROLE_ADMIN = "Quan tri vien";
    private static final String ROLE_STAFF = "Nhan vien";
    private static final String ROLE_CUSTOMER = "Khach hang";
    private static final String STATUS_ACTIVE = "Hoat dong";
    private static final String STATUS_DELETED = "Da xoa";
    private static final String STATUS_DELETED_WITH_RELATED = "Da xoa kem du lieu";

    private final UserRepository userRepository;
    private final CustomerRepository customerRepository;
    private final OrderRepository orderRepository;
    private final PasswordEncoder passwordEncoder;
    private final PhoneNumberService phoneNumberService;
    private final com.flarefitness.backend.security.RedisTokenStore redisTokenStore;
    private final AuditLogService auditLogService;

    public AdminService(
            UserRepository userRepository,
            CustomerRepository customerRepository,
            OrderRepository orderRepository,
            PasswordEncoder passwordEncoder,
            PhoneNumberService phoneNumberService,
            com.flarefitness.backend.security.RedisTokenStore redisTokenStore,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.customerRepository = customerRepository;
        this.orderRepository = orderRepository;
        this.passwordEncoder = passwordEncoder;
        this.phoneNumberService = phoneNumberService;
        this.redisTokenStore = redisTokenStore;
        this.auditLogService = auditLogService;
    }

    @Transactional(readOnly = true)
    public java.util.List<AdminUserResponse> getAllUsers() {
        return getUsersPage(0, LEGACY_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public PageResponse<AdminUserResponse> getUsersPage(Integer page, Integer size) {
        Page<User> users = userRepository.findAllByOrderByHoTenAsc(pageRequest(page, size));
        Map<String, Customer> customersByUserId = customersByUserId(users.getContent());
        List<AdminUserResponse> content = users.getContent().stream()
                .map(user -> toResponse(user, customersByUserId.get(user.getId())))
                .toList();
        return new PageResponse<>(
                content,
                users.getNumber(),
                users.getSize(),
                users.getTotalElements(),
                users.getTotalPages(),
                users.hasNext());
    }

    @Transactional
    public AdminUserResponse createUser(AdminUserRequest request) {
        String username = requireText(request.username(), "Username la bat buoc.");
        String hoTen = requireText(request.hoTen(), "Ho ten la bat buoc.");
        String email = trimToNull(request.email());
        String rawPassword = requireText(request.password(), "Mat khau la bat buoc khi tao tai khoan.");
        String role = normalizeRole(request.role());
        String status = normalizeStatus(request.status());
        String phoneNumber = ROLE_CUSTOMER.equals(role)
                ? phoneNumberService.requireAvailable(request.sdt(), null)
                : phoneNumberService.normalize(request.sdt());

        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new BadRequestException("Username da ton tai.");
        }
        if (email != null && userRepository.existsByEmailIgnoreCase(email)) {
            throw new BadRequestException("Email da duoc su dung.");
        }

        User user = new User();
        user.setId(generateUserId(role));
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(role);
        user.setHoTen(hoTen);
        user.setEmail(email);
        user.setStatus(status);
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
        syncCustomerRecord(user, phoneNumber);
        auditLogService.success("ACCOUNT_CREATE", auditLogService.currentActorId(), user.getId(), "USER", user.getId());
        return toResponse(user);
    }

    @Transactional
    public AdminUserResponse updateUser(String id, AdminUserRequest request, Authentication authentication) {
        User user = userRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay tai khoan."));
        String previousUsername = user.getUsername();
        String previousRole = user.getRole();
        String previousStatus = user.getStatus();
        String currentAdminId = currentAdmin(authentication).getId();

        String username = requireText(request.username(), "Username la bat buoc.");
        String hoTen = requireText(request.hoTen(), "Ho ten la bat buoc.");
        String email = trimToNull(request.email());
        String role = normalizeRole(request.role());
        String status = normalizeStatus(request.status());
        String phoneNumber = ROLE_CUSTOMER.equals(role)
                ? phoneNumberService.requireAvailable(request.sdt(), user.getId())
                : phoneNumberService.normalize(request.sdt());

        if (userRepository.existsByUsernameIgnoreCaseAndIdNot(username, user.getId())) {
            throw new BadRequestException("Username da ton tai.");
        }
        if (email != null && userRepository.existsByEmailIgnoreCaseAndIdNot(email, user.getId())) {
            throw new BadRequestException("Email da duoc su dung.");
        }
        if (user.getId().equals(currentAdminId)
                && (!ROLE_ADMIN.equals(role) || isInactiveStatus(status))) {
            throw new BadRequestException("Khong duoc tu ha quyen hoac khoa tai khoan dang dang nhap.");
        }

        user.setUsername(username);
        user.setRole(role);
        user.setHoTen(hoTen);
        user.setEmail(email);
        user.setStatus(status);
        String rawPassword = trimToNull(request.password());
        if (rawPassword != null) {
            user.setPassword(passwordEncoder.encode(rawPassword));
        }

        userRepository.save(user);
        if (rawPassword != null
                || isInactiveStatus(status)
                || !previousUsername.equalsIgnoreCase(user.getUsername())
                || !String.valueOf(previousRole).equalsIgnoreCase(user.getRole())) {
            redisTokenStore.revokeAll(previousUsername);
            redisTokenStore.revokeAll(user.getUsername());
        }
        syncCustomerRecord(user, phoneNumber);
        auditLogService.success("ACCOUNT_UPDATE", currentAdminId, user.getId(), "USER", user.getId());
        if (!String.valueOf(previousRole).equalsIgnoreCase(user.getRole())) {
            auditLogService.success("ACCOUNT_PRIVILEGE_CHANGE", currentAdminId, user.getId(), "USER", user.getId());
        }
        if (!String.valueOf(previousStatus).equalsIgnoreCase(user.getStatus())) {
            auditLogService.success("ACCOUNT_STATUS_CHANGE", currentAdminId, user.getId(), "USER", user.getId());
        }
        if (rawPassword != null) {
            auditLogService.success("ACCOUNT_PASSWORD_RESET", currentAdminId, user.getId(), "USER", user.getId());
        }
        return toResponse(user);
    }

    @Transactional
    public void deleteUser(String id, boolean deleteRelated, Authentication authentication) {
        User user = userRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay tai khoan."));
        String previousUsername = user.getUsername();
        if (user.getId().equals(currentAdmin(authentication).getId())) {
            throw new BadRequestException("Khong duoc xoa tai khoan dang dang nhap.");
        }

        String deletedSuffix = "__deleted__" + System.currentTimeMillis();
        user.setUsername(truncate(user.getUsername() + deletedSuffix, 100));
        if (user.getEmail() != null && !user.getEmail().isBlank()) {
            user.setEmail(truncate(user.getEmail() + deletedSuffix, 150));
        }
        user.setStatus(deleteRelated ? STATUS_DELETED_WITH_RELATED : STATUS_DELETED);
        user.setDeleted(true);
        userRepository.save(user);
        redisTokenStore.revokeAll(previousUsername);
        if (deleteRelated) {
            softDeleteRelatedCustomerData(user);
        }
        auditLogService.success(
                "ACCOUNT_DELETE",
                currentAdmin(authentication).getId(),
                user.getId(),
                "USER",
                user.getId());
    }

    private AdminUserResponse toResponse(User user) {
        return toResponse(user, customerRepository.findUniqueActiveByUserId(user.getId()).orElse(null));
    }

    private AdminUserResponse toResponse(User user, Customer customer) {
        return new AdminUserResponse(
                user.getId(),
                user.getHoTen(),
                user.getUsername(),
                user.getRole(),
                user.getEmail(),
                customer == null ? null : customer.getSdt(),
                user.getStatus(),
                user.getCreatedAt()
        );
    }

    private Map<String, Customer> customersByUserId(List<User> users) {
        if (users.isEmpty()) {
            return Map.of();
        }
        return customerRepository.findActiveByUserIdIn(users.stream().map(User::getId).toList())
                .stream()
                .collect(java.util.stream.Collectors.toMap(
                        Customer::getUserId,
                        customer -> customer,
                        (left, right) -> left));
    }

    private PageRequest pageRequest(Integer page, Integer size) {
        int safePage = Math.max(page == null ? 0 : page, 0);
        int safeSize = Math.min(Math.max(size == null ? 50 : size, 1), LEGACY_LIST_LIMIT);
        return PageRequest.of(safePage, safeSize);
    }

    private void syncCustomerRecord(User user, String phoneNumber) {
        if (!ROLE_CUSTOMER.equals(normalizeRole(user.getRole()))) {
            return;
        }
        Customer customer = customerRepository.findUniqueActiveByUserId(user.getId())
                .orElseGet(() -> {
                    Customer nextCustomer = new Customer();
                    nextCustomer.setId("customer-" + UUID.randomUUID());
                    nextCustomer.setCreatedAt(LocalDateTime.now());
                    return nextCustomer;
                });
        customer.setUserId(user.getId());
        customer.setTenKhach(user.getHoTen());
        customer.setEmail(user.getEmail());
        customer.setSdt(trimToNull(phoneNumber) == null ? defaultPhone(customer.getSdt()) : phoneNumber.trim());
        customer.setKenh(customer.getKenh() == null || customer.getKenh().isBlank() ? "Website" : customer.getKenh());
        customer.setNhan(customer.getNhan() == null || customer.getNhan().isBlank() ? "Moi" : customer.getNhan());
        customer.setTongChiTieu(customer.getTongChiTieu() == null ? BigDecimal.ZERO : customer.getTongChiTieu());
        customer.setUpdatedAt(LocalDateTime.now());
        customer.setDeleted(false);
        customerRepository.save(customer);
    }

    private void softDeleteRelatedCustomerData(User user) {
        Optional<Customer> customer = customerRepository.findUniqueByUserId(user.getId());
        String customerId = customer.map(Customer::getId).orElse(null);
        LocalDateTime now = LocalDateTime.now();

        customer.ifPresent(record -> {
            record.setDeleted(true);
            record.setTongChiTieu(BigDecimal.ZERO);
            record.setUpdatedAt(now);
            record.setGhiChu(appendAuditNote(record.getGhiChu(), "Soft-deleted with account " + user.getId()));
            customerRepository.save(record);
        });

        List<Order> orders = orderRepository.findForSoftDelete(user.getId(), customerId);
        Map<String, Order> uniqueOrders = new LinkedHashMap<>();
        orders.forEach(order -> uniqueOrders.put(order.getId(), order));
        uniqueOrders.values().forEach(order -> {
            order.setDeleted(true);
            order.setUpdatedAt(now);
            order.setGhiChu(appendAuditNote(order.getGhiChu(), "Soft-deleted with account " + user.getId()));
        });
        orderRepository.saveAll(uniqueOrders.values());
    }

    private String appendAuditNote(String current, String note) {
        String base = trimToNull(current);
        String next = base == null ? note : base + " | " + note;
        return truncate(next, 500);
    }

    private User currentAdmin(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new BadRequestException("Phien dang nhap khong hop le.");
        }
        return principal.getUser();
    }

    private String generateUserId(String role) {
        return getUserIdPrefix(role) + UUID.randomUUID();
    }

    private String getUserIdPrefix(String role) {
        return switch (normalizeRole(role)) {
            case ROLE_ADMIN -> "user-admin-";
            case ROLE_STAFF -> "user-staff-";
            default -> "user-customer-";
        };
    }

    private String normalizeRole(String role) {
        String normalized = normalize(role);
        if (normalized.contains("quan tri") || normalized.contains("admin")) {
            return ROLE_ADMIN;
        }
        if (normalized.contains("nhan vien") || normalized.contains("staff")) {
            return ROLE_STAFF;
        }
        return ROLE_CUSTOMER;
    }

    private String normalizeStatus(String status) {
        String normalized = normalize(status);
        if (normalized.contains("ngung") || normalized.contains("khoa") || normalized.contains("inactive")) {
            return "Ngung hoat dong";
        }
        return STATUS_ACTIVE;
    }

    private boolean isInactiveStatus(String status) {
        return !"Hoat dong".equals(normalizeStatus(status));
    }

    private String normalize(String value) {
        return Normalizer.normalize(String.valueOf(value == null ? "" : value), Normalizer.Form.NFD)
                .toLowerCase(Locale.ROOT)
                .replace('đ', 'd')
                .replace('Đ', 'd')
                .replaceAll("\\p{M}+", "")
                .replaceAll("[^a-z0-9]+", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private String requireText(String value, String message) {
        String trimmed = trimToNull(value);
        if (trimmed == null) {
            throw new BadRequestException(message);
        }
        return trimmed;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private String defaultPhone(String value) {
        return trimToNull(value) == null ? "0000000000" : value.trim();
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }
}
