package com.flarefitness.backend.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.flarefitness.backend.dto.voucher.VoucherAssignmentGrant;
import com.flarefitness.backend.dto.voucher.VoucherAssignmentSyncPayload;
import com.flarefitness.backend.dto.voucher.VoucherCatalogEntry;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.sync.SyncState;
import com.flarefitness.backend.entity.voucher.Voucher;
import com.flarefitness.backend.entity.voucher.VoucherAssignment;
import com.flarefitness.backend.entity.voucher.VoucherCategory;
import com.flarefitness.backend.entity.voucher.VoucherRedemption;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.voucher.VoucherAssignmentRepository;
import com.flarefitness.backend.repository.voucher.VoucherCategoryRepository;
import com.flarefitness.backend.repository.voucher.VoucherRedemptionRepository;
import com.flarefitness.backend.repository.voucher.VoucherRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.Normalizer;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Server-authoritative voucher pricing, entitlement and redemption service.
 *
 * <p>Voucher values used to be read from client-sync JSON. The compatibility sync
 * endpoints now serialize data from relational tables, while checkout and promo
 * claims use pessimistic locks plus database uniqueness constraints.</p>
 */
@Service
public class VoucherPricingService {

    public static final String SCOPE_APP = "APP";
    public static final String SCOPE_USER = "USER";
    public static final String CATALOG_KEY = "managed-vouchers";
    public static final String ASSIGNMENTS_KEY = "voucher-assignments";

    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String STATUS_DISABLED = "DISABLED";
    private static final String STATUS_DELETED = "DELETED";
    private static final String ASSIGNMENT_ACTIVE = "ACTIVE";
    private static final String ASSIGNMENT_REVOKED = "REVOKED";
    private static final String ALL_CATEGORIES = "tat ca";
    private static final int MAX_ASSIGNMENT_INCREMENT = 1_000;
    private static final int MAX_ASSIGNMENT_QUANTITY = 10_000;
    private static final int MAX_CATALOG_ENTRIES = 1_000;
    private static final int MAX_CATEGORIES_PER_VOUCHER = 50;
    private static final BigDecimal MAX_PERCENT = BigDecimal.ONE;
    private static final BigDecimal MAX_MONEY = new BigDecimal("9999999999999.99");

    private final VoucherRepository voucherRepository;
    private final VoucherCategoryRepository voucherCategoryRepository;
    private final VoucherAssignmentRepository voucherAssignmentRepository;
    private final VoucherRedemptionRepository voucherRedemptionRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final AuditLogService auditLogService;

    public VoucherPricingService(
            VoucherRepository voucherRepository,
            VoucherCategoryRepository voucherCategoryRepository,
            VoucherAssignmentRepository voucherAssignmentRepository,
            VoucherRedemptionRepository voucherRedemptionRepository,
            UserRepository userRepository,
            ObjectMapper objectMapper,
            Clock clock,
            AuditLogService auditLogService
    ) {
        this.voucherRepository = voucherRepository;
        this.voucherCategoryRepository = voucherCategoryRepository;
        this.voucherAssignmentRepository = voucherAssignmentRepository;
        this.voucherRedemptionRepository = voucherRedemptionRepository;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.auditLogService = auditLogService;
    }

    /**
     * Validates, consumes and audits a voucher in the caller's transaction. The
     * order service is already transactional, so a failed order rolls this usage
     * back together with inventory and order persistence.
     */
    @Transactional
    public VoucherPricing applyVoucher(
            User user,
            String requestedCode,
            BigDecimal subtotal,
            List<Product> products,
            String orderId
    ) {
        if (subtotal == null || subtotal.signum() < 0) {
            throw new BadRequestException("Tong tien don hang khong hop le.");
        }

        String code = normalizeCode(requestedCode);
        if (code == null) {
            return VoucherPricing.none(subtotal);
        }
        String normalizedOrderId = trimToNull(orderId);
        if (normalizedOrderId == null) {
            throw new BadRequestException("Don hang ap dung ma giam gia khong hop le.");
        }
        requireUserId(user);

        // Lock the voucher first, then the user assignment. grantVoucher follows
        // the same ordering, preventing conflicting lock order during checkout.
        Voucher voucher = voucherRepository.findByCodeForUpdate(code)
                .orElseThrow(() -> new BadRequestException("Ma giam gia khong ton tai."));
        validateVoucherForCheckout(voucher, subtotal, products);

        VoucherAssignment assignment = voucherAssignmentRepository
                .findByUserIdAndVoucherCodeForUpdate(user.getId(), code)
                .orElseThrow(() -> new BadRequestException("Tai khoan chua duoc cap ma giam gia nay."));

        if (!ASSIGNMENT_ACTIVE.equals(assignment.getStatus())) {
            throw new BadRequestException("Ma giam gia da bi thu hoi.");
        }
        int quantity = nonNegative(assignment.getQuantity());
        int used = nonNegative(assignment.getUsedQuantity());
        if (quantity == 0 || used >= quantity) {
            throw new BadRequestException("Ma giam gia da het luot su dung.");
        }

        BigDecimal discount = calculateDiscount(voucher, subtotal);
        LocalDateTime now = LocalDateTime.now(clock);
        assignment.setUsedQuantity(used + 1);
        assignment.setUpdatedAt(now);
        voucherAssignmentRepository.save(assignment);

        VoucherRedemption redemption = new VoucherRedemption();
        redemption.setId("vredeem-" + UUID.randomUUID());
        redemption.setAssignmentId(assignment.getId());
        redemption.setUserId(user.getId());
        redemption.setVoucherCode(voucher.getCode());
        redemption.setOrderId(normalizedOrderId);
        redemption.setSubtotal(scaleMoney(subtotal));
        redemption.setDiscountAmount(discount);
        redemption.setRedeemedAt(now);
        redemption.setCreatedAt(now);
        voucherRedemptionRepository.save(redemption);
        auditLogService.success("VOUCHER_REDEMPTION", user.getId(), user.getId(), "VOUCHER", voucher.getCode());

        return new VoucherPricing(
                voucher.getCode(),
                voucher.getLabel(),
                discount,
                scaleMoney(subtotal.subtract(discount).max(BigDecimal.ZERO))
        );
    }

    /**
     * Grants more uses of an existing voucher. This method is server-only; callers
     * must already have performed their authorization check (promo hunt does so).
     */
    @Transactional
    public void grantVoucher(User user, String requestedCode, int quantity) {
        requireUserId(user);
        if (quantity < 1 || quantity > MAX_ASSIGNMENT_INCREMENT) {
            throw new BadRequestException("So luot cap ma giam gia khong hop le.");
        }

        String code = normalizeCode(requestedCode);
        if (code == null) {
            throw new BadRequestException("Ma giam gia khong ton tai.");
        }

        Voucher voucher = voucherRepository.findByCodeForUpdate(code)
                .orElseThrow(() -> new BadRequestException("Ma giam gia khong ton tai."));
        validateVoucherCanBeGranted(voucher);

        LocalDateTime now = LocalDateTime.now(clock);
        VoucherAssignment assignment = voucherAssignmentRepository
                .findByUserIdAndVoucherCodeForUpdate(user.getId(), code)
                .orElseGet(() -> newAssignment(user.getId(), code, now));

        boolean reactivating = !ASSIGNMENT_ACTIVE.equals(assignment.getStatus());
        int currentQuantity = nonNegative(assignment.getQuantity());
        int usedQuantity = nonNegative(assignment.getUsedQuantity());
        if (currentQuantity > MAX_ASSIGNMENT_QUANTITY - quantity) {
            throw new BadRequestException("So luot cap ma giam gia vuot qua gioi han cho phep.");
        }
        assignment.setQuantity(currentQuantity + quantity);
        assignment.setUsedQuantity(Math.min(usedQuantity, assignment.getQuantity()));
        assignment.setStatus(ASSIGNMENT_ACTIVE);
        if (assignment.getAssignedAt() == null || reactivating) {
            assignment.setAssignedAt(now);
        }
        assignment.setUpdatedAt(now);
        voucherAssignmentRepository.save(assignment);
        auditLogService.success(
                "VOUCHER_GRANT",
                auditLogService.currentActorId(),
                user.getId(),
                "VOUCHER",
                voucher.getCode());
    }

    /** Staff/admin API path for explicitly granting a voucher to a customer. */
    @Transactional
    public SyncState grantVoucherToUser(String targetUserId, String requestedCode, int quantity) {
        User user = requireActiveCustomerForUpdate(targetUserId);
        grantVoucher(user, requestedCode, quantity);
        return ensureAssignments(user);
    }

    /** Read-only staff/admin path for the customer's current entitlement. */
    @Transactional(readOnly = true)
    public SyncState getAssignmentsForUser(String targetUserId) {
        return ensureAssignments(requireActiveCustomer(targetUserId));
    }

    /**
     * Revocation preserves historical redemption rows and discards only unused
     * entitlement. A later explicit grant reactivates the same unique assignment.
     */
    @Transactional
    public SyncState revokeVoucherForUser(String targetUserId, String requestedCode) {
        User user = requireActiveCustomerForUpdate(targetUserId);
        String code = normalizeCode(requestedCode);
        if (code == null) {
            throw new BadRequestException("Ma giam gia khong ton tai.");
        }
        voucherRepository.findByCodeForUpdate(code)
                .orElseThrow(() -> new BadRequestException("Ma giam gia khong ton tai."));
        VoucherAssignment assignment = voucherAssignmentRepository
                .findByUserIdAndVoucherCodeForUpdate(user.getId(), code)
                .orElseThrow(() -> new BadRequestException("Tai khoan chua duoc cap ma giam gia nay."));

        int quantity = nonNegative(assignment.getQuantity());
        int used = Math.min(quantity, nonNegative(assignment.getUsedQuantity()));
        assignment.setQuantity(used);
        assignment.setUsedQuantity(used);
        assignment.setStatus(ASSIGNMENT_REVOKED);
        assignment.setUpdatedAt(LocalDateTime.now(clock));
        voucherAssignmentRepository.save(assignment);
        auditLogService.success(
                "VOUCHER_REVOKE",
                auditLogService.currentActorId(),
                user.getId(),
                "VOUCHER",
                code);
        return ensureAssignments(user);
    }

    /**
     * Validates a promo campaign's voucher before the campaign is persisted.
     */
    @Transactional(readOnly = true)
    public void validateVoucherCanBeGranted(String requestedCode, LocalDateTime campaignEndAt) {
        String code = normalizeCode(requestedCode);
        if (code == null) {
            throw new BadRequestException("Ma giam gia khong ton tai.");
        }
        Voucher voucher = voucherRepository.findById(code)
                .orElseThrow(() -> new BadRequestException("Ma giam gia khong ton tai."));
        validateVoucherCanBeGranted(voucher);
        if (campaignEndAt != null && voucher.getExpiresAt() != null
                && voucher.getExpiresAt().isBefore(campaignEndAt.toLocalDate())) {
            throw new BadRequestException("Ma giam gia het han truoc khi chien dich ket thuc.");
        }
    }

    /**
     * Compatibility shape for GET /api/sync/me/voucher-assignments. It is never
     * stored back in sync-state, so clients cannot overwrite entitlements.
     */
    @Transactional(readOnly = true)
    public SyncState ensureAssignments(User user) {
        requireUserId(user);
        List<VoucherAssignment> assignments = voucherAssignmentRepository
                .findActiveByUserIdOrderByAssignedAtDescVoucherCodeAsc(user.getId());
        Map<String, VoucherAssignmentGrant> grants = new LinkedHashMap<>();
        LocalDateTime updatedAt = null;
        for (VoucherAssignment assignment : assignments) {
            int quantity = nonNegative(assignment.getQuantity());
            int used = Math.min(quantity, nonNegative(assignment.getUsedQuantity()));
            grants.put(assignment.getVoucherCode(), new VoucherAssignmentGrant(
                    assignment.getVoucherCode(), quantity, used, assignment.getAssignedAt()));
            updatedAt = latest(updatedAt, assignment.getUpdatedAt());
        }

        VoucherAssignmentSyncPayload payload = new VoucherAssignmentSyncPayload(
                user.getId(),
                firstNonBlank(user.getHoTen(), user.getUsername(), user.getId()),
                List.copyOf(grants.keySet()),
                Map.copyOf(grants),
                updatedAt
        );
        return syncState(SCOPE_USER, user.getId(), ASSIGNMENTS_KEY, writeJson(payload), updatedAt);
    }

    /**
     * Compatibility shape for GET /api/sync/app/managed-vouchers.
     */
    @Transactional(readOnly = true)
    public SyncState getManagedVoucherCatalog() {
        List<Voucher> vouchers = voucherRepository.findAllVisible();
        Map<String, List<String>> categoriesByCode = categoriesByVoucherCode(
                vouchers.stream().map(Voucher::getCode).toList());
        List<VoucherCatalogEntry> payload = vouchers.stream()
                .map(voucher -> toCatalogEntry(voucher, categoriesByCode.get(voucher.getCode())))
                .toList();
        LocalDateTime updatedAt = vouchers.stream()
                .map(Voucher::getUpdatedAt)
                .filter(Objects::nonNull)
                .max(Comparator.naturalOrder())
                .orElse(null);
        return syncState(SCOPE_APP, null, CATALOG_KEY, writeJson(payload), updatedAt);
    }

    /**
     * Staff compatibility path for PUT /api/sync/app/managed-vouchers. The entire
     * catalog is replaced atomically; missing entries are soft-deleted so historic
     * assignments and redemptions remain referentially intact.
     */
    @Transactional
    public SyncState replaceManagedVoucherCatalog(String rawPayload) {
        List<IncomingVoucher> incoming = parseCatalog(rawPayload);
        Map<String, IncomingVoucher> incomingByCode = new LinkedHashMap<>();
        incoming.stream().sorted(Comparator.comparing(IncomingVoucher::code))
                .forEach(voucher -> incomingByCode.put(voucher.code(), voucher));

        // Lock visible vouchers in deterministic code order before changing them.
        List<String> currentCodes = voucherRepository.findAllVisible().stream()
                .map(Voucher::getCode)
                .sorted()
                .toList();
        LocalDateTime now = LocalDateTime.now(clock);
        for (Map.Entry<String, IncomingVoucher> entry : incomingByCode.entrySet()) {
            Voucher voucher = voucherRepository.findByCodeForUpdate(entry.getKey())
                    .orElseGet(() -> newVoucher(entry.getKey(), now));
            applyIncomingVoucher(voucher, entry.getValue(), now);
            voucherRepository.save(voucher);
            replaceCategories(voucher.getCode(), entry.getValue().categories());
        }

        for (String code : currentCodes) {
            if (incomingByCode.containsKey(code)) {
                continue;
            }
            Voucher voucher = voucherRepository.findByCodeForUpdate(code).orElse(null);
            if (voucher != null && !STATUS_DELETED.equals(voucher.getStatus())) {
                voucher.setStatus(STATUS_DELETED);
                voucher.setUpdatedAt(now);
                voucherRepository.save(voucher);
            }
        }
        return getManagedVoucherCatalog();
    }

    private VoucherAssignment newAssignment(String userId, String voucherCode, LocalDateTime now) {
        VoucherAssignment assignment = new VoucherAssignment();
        assignment.setId("vassign-" + UUID.randomUUID());
        assignment.setUserId(userId);
        assignment.setVoucherCode(voucherCode);
        assignment.setQuantity(0);
        assignment.setUsedQuantity(0);
        assignment.setStatus(ASSIGNMENT_ACTIVE);
        assignment.setAssignedAt(now);
        assignment.setCreatedAt(now);
        assignment.setUpdatedAt(now);
        return assignment;
    }

    private Voucher newVoucher(String code, LocalDateTime now) {
        Voucher voucher = new Voucher();
        voucher.setCode(code);
        voucher.setCreatedAt(now);
        voucher.setUpdatedAt(now);
        return voucher;
    }

    private void applyIncomingVoucher(Voucher voucher, IncomingVoucher incoming, LocalDateTime now) {
        voucher.setLabel(incoming.label());
        voucher.setDiscountPercent(incoming.percent());
        voucher.setMinimumOrder(incoming.minOrder());
        voucher.setMaximumDiscount(incoming.maxDiscount());
        voucher.setExpiresAt(incoming.expiresAt());
        voucher.setStatus(incoming.status());
        voucher.setUpdatedAt(now);
    }

    private void replaceCategories(String voucherCode, List<CategoryValue> categories) {
        voucherCategoryRepository.deleteByVoucherCode(voucherCode);
        List<VoucherCategory> entities = new ArrayList<>();
        for (CategoryValue category : categories) {
            VoucherCategory entity = new VoucherCategory();
            entity.setId("vcat-" + UUID.randomUUID());
            entity.setVoucherCode(voucherCode);
            entity.setCategoryKey(category.key());
            entity.setCategoryLabel(category.label());
            entities.add(entity);
        }
        voucherCategoryRepository.saveAll(entities);
    }

    private void validateVoucherForCheckout(Voucher voucher, BigDecimal subtotal, List<Product> products) {
        validateVoucherCanBeGranted(voucher);
        if (subtotal.compareTo(voucher.getMinimumOrder()) < 0) {
            throw new BadRequestException("Don hang chua dat gia tri toi thieu cua ma giam gia.");
        }

        List<String> categories = voucherCategoryRepository
                .findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(List.of(voucher.getCode()))
                .stream()
                .map(VoucherCategory::getCategoryKey)
                .map(this::normalize)
                .filter(value -> !value.isBlank())
                .toList();
        if (categories.isEmpty() || categories.contains(ALL_CATEGORIES)) {
            return;
        }

        boolean matches = products != null && products.stream()
                .filter(Objects::nonNull)
                .map(Product::getDanhMuc)
                .map(this::normalize)
                .anyMatch(categories::contains);
        if (!matches) {
            throw new BadRequestException("Ma giam gia khong ap dung cho san pham trong don hang.");
        }
    }

    private void validateVoucherCanBeGranted(Voucher voucher) {
        if (voucher.getDiscountPercent() == null || voucher.getDiscountPercent().signum() <= 0
                || voucher.getDiscountPercent().compareTo(MAX_PERCENT) > 0) {
            throw new BadRequestException("Ma giam gia khong co muc giam hop le.");
        }
        if (!STATUS_ACTIVE.equals(voucher.getStatus())) {
            throw new BadRequestException("Ma giam gia dang tam khoa.");
        }
        if (voucher.getExpiresAt() != null && voucher.getExpiresAt().isBefore(LocalDate.now(clock))) {
            throw new BadRequestException("Ma giam gia da het han.");
        }
    }

    private BigDecimal calculateDiscount(Voucher voucher, BigDecimal subtotal) {
        BigDecimal rawDiscount = subtotal.multiply(voucher.getDiscountPercent());
        BigDecimal maximum = voucher.getMaximumDiscount() == null ? BigDecimal.ZERO : voucher.getMaximumDiscount();
        BigDecimal discount = maximum.signum() > 0 ? rawDiscount.min(maximum) : rawDiscount;
        return scaleMoney(discount.max(BigDecimal.ZERO).min(subtotal));
    }

    private Map<String, List<String>> categoriesByVoucherCode(Collection<String> voucherCodes) {
        if (voucherCodes == null || voucherCodes.isEmpty()) {
            return Map.of();
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (VoucherCategory category : voucherCategoryRepository
                .findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(voucherCodes)) {
            result.computeIfAbsent(category.getVoucherCode(), unused -> new ArrayList<>())
                    .add(category.getCategoryLabel());
        }
        return result;
    }

    private VoucherCatalogEntry toCatalogEntry(Voucher voucher, List<String> categories) {
        List<String> visibleCategories = categories == null || categories.isEmpty()
                ? List.of("Tất cả")
                : List.copyOf(categories);
        return new VoucherCatalogEntry(
                voucher.getCode(),
                voucher.getLabel(),
                voucher.getDiscountPercent(),
                voucher.getMinimumOrder(),
                voucher.getMaximumDiscount(),
                visibleCategories,
                voucher.getExpiresAt(),
                toStatusLabel(voucher.getStatus())
        );
    }

    private List<IncomingVoucher> parseCatalog(String rawPayload) {
        if (rawPayload == null || rawPayload.isBlank()) {
            throw new BadRequestException("Danh sach ma giam gia khong hop le.");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(rawPayload);
        } catch (JsonProcessingException exception) {
            throw new BadRequestException("Danh sach ma giam gia phai la JSON hop le.");
        }
        if (!(root instanceof ArrayNode arrayNode) || arrayNode.size() > MAX_CATALOG_ENTRIES) {
            throw new BadRequestException("Danh sach ma giam gia khong hop le.");
        }

        List<IncomingVoucher> result = new ArrayList<>();
        Map<String, Boolean> seenCodes = new LinkedHashMap<>();
        for (JsonNode node : arrayNode) {
            IncomingVoucher incoming = parseIncomingVoucher(node);
            if (seenCodes.put(incoming.code(), Boolean.TRUE) != null) {
                throw new BadRequestException("Danh sach ma giam gia co ma trung lap.");
            }
            result.add(incoming);
        }
        return result;
    }

    private IncomingVoucher parseIncomingVoucher(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new BadRequestException("Thong tin ma giam gia khong hop le.");
        }
        String code = normalizeCode(node.path("code").asText());
        if (code == null || !code.matches("[A-Z0-9_-]{2,64}")) {
            throw new BadRequestException("Ma giam gia chi gom chu in hoa, so, gach ngang hoac gach duoi.");
        }
        String label = trimToNull(node.path("label").asText());
        if (label == null || label.length() > 255) {
            throw new BadRequestException("Nhan ma giam gia khong hop le.");
        }
        BigDecimal percent = requiredDecimal(node.path("percent"), "Ty le giam gia", 4);
        if (percent.signum() <= 0 || percent.compareTo(MAX_PERCENT) > 0) {
            throw new BadRequestException("Ty le giam gia phai lon hon 0 va khong qua 100%.");
        }
        BigDecimal minOrder = nonNegativeMoney(node.path("minOrder"), "Gia tri don toi thieu");
        BigDecimal maxDiscount = nonNegativeMoney(node.path("maxDiscount"), "Muc giam toi da");
        LocalDate expiresAt = parseExpiry(node.path("expiresAt"));
        String status = parseStatus(node.path("status").asText(STATUS_ACTIVE));
        List<CategoryValue> categories = parseCategories(node.path("categories"));
        return new IncomingVoucher(code, label, percent, minOrder, maxDiscount, expiresAt, status, categories);
    }

    private BigDecimal requiredDecimal(JsonNode value, String field, int maximumScale) {
        String raw = trimToNull(value == null ? null : value.asText());
        if (raw == null) {
            throw new BadRequestException(field + " khong hop le.");
        }
        try {
            BigDecimal decimal = new BigDecimal(raw);
            if (decimal.scale() > maximumScale || decimal.abs().compareTo(MAX_MONEY) > 0) {
                throw new BadRequestException(field + " khong hop le.");
            }
            return decimal;
        } catch (NumberFormatException exception) {
            throw new BadRequestException(field + " khong hop le.");
        }
    }

    private BigDecimal nonNegativeMoney(JsonNode value, String field) {
        BigDecimal decimal = requiredDecimal(value, field, 2);
        if (decimal.signum() < 0) {
            throw new BadRequestException(field + " khong hop le.");
        }
        return decimal;
    }

    private LocalDate parseExpiry(JsonNode value) {
        String raw = trimToNull(value == null ? null : value.asText());
        if (raw == null) {
            return null;
        }
        try {
            return LocalDate.parse(raw);
        } catch (RuntimeException exception) {
            throw new BadRequestException("Ngay het han khong hop le.");
        }
    }

    private List<CategoryValue> parseCategories(JsonNode categoryNode) {
        List<String> rawCategories = new ArrayList<>();
        if (categoryNode != null && categoryNode.isArray()) {
            categoryNode.forEach(value -> rawCategories.add(value.asText()));
        } else if (categoryNode != null && !categoryNode.isMissingNode() && !categoryNode.isNull()) {
            String raw = categoryNode.asText();
            for (String part : raw.split("[,\\n/|;]+")) {
                rawCategories.add(part);
            }
        }

        Map<String, CategoryValue> result = new LinkedHashMap<>();
        for (String raw : rawCategories) {
            String label = trimToNull(raw);
            String key = normalize(label);
            if (label == null || key.isBlank()) {
                continue;
            }
            if (label.length() > 100 || key.length() > 160) {
                throw new BadRequestException("Danh muc ap dung cua ma giam gia khong hop le.");
            }
            result.putIfAbsent(key, new CategoryValue(key, label));
        }
        if (result.isEmpty()) {
            result.put(ALL_CATEGORIES, new CategoryValue(ALL_CATEGORIES, "Tất cả"));
        }
        if (result.size() > MAX_CATEGORIES_PER_VOUCHER) {
            throw new BadRequestException("Ma giam gia co qua nhieu danh muc ap dung.");
        }
        return List.copyOf(result.values());
    }

    private String parseStatus(String rawStatus) {
        String normalized = normalize(rawStatus);
        if (normalized.isBlank() || "active".equals(normalized) || "hoat dong".equals(normalized)
                || "dang mo".equals(normalized)) {
            return STATUS_ACTIVE;
        }
        if ("disabled".equals(normalized) || "tam khoa".equals(normalized)) {
            return STATUS_DISABLED;
        }
        if ("deleted".equals(normalized) || "da xoa".equals(normalized)) {
            return STATUS_DELETED;
        }
        throw new BadRequestException("Trang thai ma giam gia khong hop le.");
    }

    private String toStatusLabel(String status) {
        if (STATUS_DISABLED.equals(status)) {
            return "Tạm khóa";
        }
        if (STATUS_DELETED.equals(status)) {
            return "Đã xóa";
        }
        return "Hoạt động";
    }

    private SyncState syncState(String scope, String ownerId, String key, String payload, LocalDateTime updatedAt) {
        SyncState state = new SyncState();
        state.setId(scope.toLowerCase(Locale.ROOT) + ":" + (ownerId == null ? "global" : ownerId) + ":" + key);
        state.setScope(scope);
        state.setOwnerId(ownerId);
        state.setKeyName(key);
        state.setPayload(payload);
        state.setUpdatedAt(updatedAt);
        return state;
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException exception) {
            throw new BadRequestException("Khong the doc du lieu ma giam gia.");
        }
    }

    private void requireUserId(User user) {
        if (user == null || trimToNull(user.getId()) == null) {
            throw new BadRequestException("Tai khoan khong hop le.");
        }
    }

    private User requireActiveCustomerForUpdate(String targetUserId) {
        return validateCustomer(userRepository.findActiveByIdForUpdate(validateTargetUserId(targetUserId)));
    }

    private User requireActiveCustomer(String targetUserId) {
        return validateCustomer(userRepository.findActiveById(validateTargetUserId(targetUserId)));
    }

    private String validateTargetUserId(String targetUserId) {
        String userId = trimToNull(targetUserId);
        if (userId == null || userId.length() > 64) {
            throw new BadRequestException("Tai khoan khach hang khong hop le.");
        }
        return userId;
    }

    private User validateCustomer(java.util.Optional<User> userResult) {
        User user = userResult
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay tai khoan khach hang."));
        String authority = CurrentUserPrincipal.toAuthority(user.getRole());
        if ("ROLE_ADMIN".equals(authority) || "ROLE_STAFF".equals(authority)) {
            throw new BadRequestException("Voucher chi co the cap cho tai khoan khach hang.");
        }
        return user;
    }

    private int nonNegative(Integer value) {
        return value == null ? 0 : Math.max(0, value);
    }

    private BigDecimal scaleMoney(BigDecimal value) {
        return value.setScale(2, RoundingMode.HALF_UP);
    }

    private LocalDateTime latest(LocalDateTime left, LocalDateTime right) {
        if (left == null || (right != null && right.isAfter(left))) {
            return right;
        }
        return left;
    }

    private String normalizeCode(String value) {
        String code = trimToNull(value);
        return code == null ? null : code.toUpperCase(Locale.ROOT);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            String trimmed = trimToNull(value);
            if (trimmed != null && !"null".equalsIgnoreCase(trimmed)) {
                return trimmed;
            }
        }
        return "";
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
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

    public record VoucherPricing(String code, String label, BigDecimal discount, BigDecimal total) {
        public static VoucherPricing none(BigDecimal subtotal) {
            BigDecimal safeSubtotal = subtotal == null ? BigDecimal.ZERO : subtotal;
            return new VoucherPricing("", "", BigDecimal.ZERO.setScale(2), safeSubtotal.setScale(2, RoundingMode.HALF_UP));
        }
    }

    private record IncomingVoucher(
            String code,
            String label,
            BigDecimal percent,
            BigDecimal minOrder,
            BigDecimal maxDiscount,
            LocalDate expiresAt,
            String status,
            List<CategoryValue> categories
    ) {
    }

    private record CategoryValue(String key, String label) {
    }
}
