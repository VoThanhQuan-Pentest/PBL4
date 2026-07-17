package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.voucher.Voucher;
import com.flarefitness.backend.entity.voucher.VoucherAssignment;
import com.flarefitness.backend.entity.voucher.VoucherCategory;
import com.flarefitness.backend.entity.voucher.VoucherRedemption;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.voucher.VoucherAssignmentRepository;
import com.flarefitness.backend.repository.voucher.VoucherCategoryRepository;
import com.flarefitness.backend.repository.voucher.VoucherRedemptionRepository;
import com.flarefitness.backend.repository.voucher.VoucherRepository;
import com.flarefitness.backend.repository.UserRepository;
import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VoucherPricingServiceTest {

    @Mock
    private VoucherRepository voucherRepository;
    @Mock
    private VoucherCategoryRepository voucherCategoryRepository;
    @Mock
    private VoucherAssignmentRepository voucherAssignmentRepository;
    @Mock
    private VoucherRedemptionRepository voucherRedemptionRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private AuditLogService auditLogService;

    private VoucherPricingService voucherPricingService;
    private User user;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(Instant.parse("2026-05-01T00:00:00Z"), ZoneId.of("Asia/Ho_Chi_Minh"));
        voucherPricingService = new VoucherPricingService(
                voucherRepository,
                voucherCategoryRepository,
                voucherAssignmentRepository,
                voucherRedemptionRepository,
                userRepository,
                new ObjectMapper().findAndRegisterModules(),
                clock,
                auditLogService
        );
        user = new User();
        user.setId("user-1");
        user.setUsername("customer-1");
    }

    @Test
    void appliesDatabaseVoucherConsumesAssignmentAndWritesRedemption() {
        Voucher voucher = activeVoucher("HOTDEAL10");
        VoucherAssignment assignment = assignment("HOTDEAL10", 2, 0);
        when(voucherRepository.findByCodeForUpdate("HOTDEAL10")).thenReturn(Optional.of(voucher));
        when(voucherCategoryRepository.findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(anyCollection()))
                .thenReturn(List.of(category("HOTDEAL10", "tat ca", "Tất cả")));
        when(voucherAssignmentRepository.findByUserIdAndVoucherCodeForUpdate(user.getId(), "HOTDEAL10"))
                .thenReturn(Optional.of(assignment));

        VoucherPricingService.VoucherPricing pricing = voucherPricingService.applyVoucher(
                user,
                "hotdeal10",
                new BigDecimal("890000"),
                List.of(product("Bóng đá")),
                "order-1"
        );

        assertThat(pricing.code()).isEqualTo("HOTDEAL10");
        assertThat(pricing.discount()).isEqualByComparingTo("89000.00");
        assertThat(pricing.total()).isEqualByComparingTo("801000.00");
        assertThat(assignment.getUsedQuantity()).isEqualTo(1);
        verify(voucherAssignmentRepository).save(assignment);
        ArgumentCaptor<VoucherRedemption> redemption = ArgumentCaptor.forClass(VoucherRedemption.class);
        verify(voucherRedemptionRepository).save(redemption.capture());
        assertThat(redemption.getValue().getVoucherCode()).isEqualTo("HOTDEAL10");
        assertThat(redemption.getValue().getUserId()).isEqualTo(user.getId());
        assertThat(redemption.getValue().getOrderId()).isEqualTo("order-1");
        assertThat(redemption.getValue().getDiscountAmount()).isEqualByComparingTo("89000.00");
        verify(auditLogService).success("VOUCHER_REDEMPTION", "user-1", "user-1", "VOUCHER", "HOTDEAL10");
    }

    @Test
    void rejectsVoucherNotInDatabaseCatalog() {
        when(voucherRepository.findByCodeForUpdate("FAKE99")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> voucherPricingService.applyVoucher(
                user,
                "FAKE99",
                new BigDecimal("890000"),
                List.of(product("Bóng đá")),
                "order-1"
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("khong ton tai");
    }

    @Test
    void rejectsAssignmentWithNoRemainingUseWithoutWritingRedemption() {
        Voucher voucher = activeVoucher("HOTDEAL10");
        VoucherAssignment assignment = assignment("HOTDEAL10", 1, 1);
        when(voucherRepository.findByCodeForUpdate("HOTDEAL10")).thenReturn(Optional.of(voucher));
        when(voucherCategoryRepository.findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(anyCollection()))
                .thenReturn(List.of(category("HOTDEAL10", "tat ca", "Tất cả")));
        when(voucherAssignmentRepository.findByUserIdAndVoucherCodeForUpdate(user.getId(), "HOTDEAL10"))
                .thenReturn(Optional.of(assignment));

        assertThatThrownBy(() -> voucherPricingService.applyVoucher(
                user,
                "HOTDEAL10",
                new BigDecimal("890000"),
                List.of(product("Bóng đá")),
                "order-1"
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("het luot");
    }

    @Test
    void rejectsVoucherForWrongProductCategory() {
        Voucher voucher = activeVoucher("FOOTBALL12");
        VoucherAssignment assignment = assignment("FOOTBALL12", 1, 0);
        when(voucherRepository.findByCodeForUpdate("FOOTBALL12")).thenReturn(Optional.of(voucher));
        when(voucherCategoryRepository.findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(anyCollection()))
                .thenReturn(List.of(category("FOOTBALL12", "bong da", "Bóng đá")));

        assertThatThrownBy(() -> voucherPricingService.applyVoucher(
                user,
                "FOOTBALL12",
                new BigDecimal("890000"),
                List.of(product("Chạy bộ")),
                "order-1"
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("khong ap dung");
    }

    @Test
    void grantUsesDatabaseAssignmentInsteadOfDefaultUsernameRules() {
        Voucher voucher = activeVoucher("HOTDEAL10");
        VoucherAssignment assignment = assignment("HOTDEAL10", 2, 1);
        when(voucherRepository.findByCodeForUpdate("HOTDEAL10")).thenReturn(Optional.of(voucher));
        when(voucherAssignmentRepository.findByUserIdAndVoucherCodeForUpdate(user.getId(), "HOTDEAL10"))
                .thenReturn(Optional.of(assignment));

        voucherPricingService.grantVoucher(user, "hotdeal10", 3);

        assertThat(assignment.getQuantity()).isEqualTo(5);
        assertThat(assignment.getUsedQuantity()).isEqualTo(1);
        verify(voucherAssignmentRepository).save(assignment);
        verify(auditLogService).success("VOUCHER_GRANT", null, "user-1", "VOUCHER", "HOTDEAL10");
    }

    @Test
    void serializesDatabaseAssignmentsInTheLegacySyncPayloadShape() {
        VoucherAssignment assignment = assignment("HOTDEAL10", 2, 1);
        when(voucherAssignmentRepository.findActiveByUserIdOrderByAssignedAtDescVoucherCodeAsc(user.getId()))
                .thenReturn(List.of(assignment));

        String payload = voucherPricingService.ensureAssignments(user).getPayload();

        assertThat(payload).contains("\"accountKey\":\"user-1\"");
        assertThat(payload).contains("\"HOTDEAL10\"");
        assertThat(payload).contains("\"quantity\":2");
        assertThat(payload).contains("\"used\":1");
    }

    @Test
    void readsCurrentAssignmentsForAnAdminSelectedCustomer() {
        VoucherAssignment assignment = assignment("HOTDEAL10", 2, 1);
        when(userRepository.findActiveById(user.getId())).thenReturn(Optional.of(user));
        when(voucherAssignmentRepository.findActiveByUserIdOrderByAssignedAtDescVoucherCodeAsc(user.getId()))
                .thenReturn(List.of(assignment));

        String payload = voucherPricingService.getAssignmentsForUser(user.getId()).getPayload();

        assertThat(payload).contains("\"HOTDEAL10\"");
        verify(userRepository).findActiveById(user.getId());
    }

    @Test
    void rejectsInvalidCatalogPayloadBeforeChangingData() {
        assertThatThrownBy(() -> voucherPricingService.replaceManagedVoucherCatalog("{}"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Danh sach ma giam gia");
    }

    private Voucher activeVoucher(String code) {
        Voucher voucher = new Voucher();
        voucher.setCode(code);
        voucher.setLabel("Giảm giá");
        voucher.setDiscountPercent(new BigDecimal("0.10"));
        voucher.setMinimumOrder(new BigDecimal("500000"));
        voucher.setMaximumDiscount(new BigDecimal("120000"));
        voucher.setExpiresAt(LocalDate.of(2026, 12, 31));
        voucher.setStatus("ACTIVE");
        voucher.setUpdatedAt(LocalDateTime.of(2026, 4, 1, 0, 0));
        return voucher;
    }

    private VoucherAssignment assignment(String code, int quantity, int used) {
        VoucherAssignment assignment = new VoucherAssignment();
        assignment.setId("vassign-1");
        assignment.setUserId(user.getId());
        assignment.setVoucherCode(code);
        assignment.setQuantity(quantity);
        assignment.setUsedQuantity(used);
        assignment.setStatus("ACTIVE");
        assignment.setAssignedAt(LocalDateTime.of(2026, 4, 1, 0, 0));
        assignment.setUpdatedAt(LocalDateTime.of(2026, 4, 1, 0, 0));
        return assignment;
    }

    private VoucherCategory category(String voucherCode, String key, String label) {
        VoucherCategory category = new VoucherCategory();
        category.setId("vcat-1");
        category.setVoucherCode(voucherCode);
        category.setCategoryKey(key);
        category.setCategoryLabel(label);
        return category;
    }

    private Product product(String category) {
        Product product = new Product();
        product.setId("product-1");
        product.setDanhMuc(category);
        return product;
    }
}
