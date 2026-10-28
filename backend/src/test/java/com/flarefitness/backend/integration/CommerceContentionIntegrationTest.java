package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.dto.order.OrderAddressPayload;
import com.flarefitness.backend.dto.order.OrderItemPayload;
import com.flarefitness.backend.dto.order.OrderRequest;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.promo.PromoHuntCampaign;
import com.flarefitness.backend.entity.voucher.Voucher;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.promo.PromoHuntCampaignRepository;
import com.flarefitness.backend.repository.voucher.VoucherRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.OrderService;
import com.flarefitness.backend.service.PromoHuntService;
import com.flarefitness.backend.service.VoucherPricingService;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Independent committed transactions against disposable MySQL, never a live database. */
@SpringBootTest
@Timeout(60)
class CommerceContentionIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private UserRepository users;
    @Autowired private ProductRepository products;
    @Autowired private VoucherRepository vouchers;
    @Autowired private PromoHuntCampaignRepository campaigns;
    @Autowired private OrderService orders;
    @Autowired private VoucherPricingService pricing;
    @Autowired private PromoHuntService promotions;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactions;

    @Test
    void twoCustomersCannotPurchaseTheSameLastStockUnit() throws Exception {
        Product product = product(1);
        User first = customer(), second = customer();
        race(() -> orders.createOrder(auth(first), request(product, null)),
                () -> orders.createOrder(auth(second), request(product, null)), "khong du ton kho");

        assertThat(products.findById(product.getId()).orElseThrow().getTonKho()).isZero();
        assertThat(count("SELECT COUNT(*) FROM tbl_chi_tiet_don_hang WHERE product_id=?", product.getId()))
                .isEqualTo(1);
        assertThat(count("SELECT COALESCE(SUM(so_luong),0) FROM tbl_chi_tiet_don_hang WHERE product_id=?", product.getId()))
                .isEqualTo(1);
    }

    @Test
    void twoCheckoutsCannotConsumeTheSameLastVoucherUse() throws Exception {
        User user = customer();
        Product product = product(2);
        Voucher voucher = voucher();
        pricing.grantVoucher(user, voucher.getCode(), 1);
        // Both valid order parents are committed before competing at the voucher boundary.
        String first = orders.createOrder(auth(user), request(product, null)).id();
        String second = orders.createOrder(auth(user), request(product, null)).id();
        race(() -> pricing.applyVoucher(user, voucher.getCode(), product.getGiaBan(), List.of(product), first),
                () -> pricing.applyVoucher(user, voucher.getCode(), product.getGiaBan(), List.of(product), second),
                "het luot su dung");

        assertThat(count("SELECT so_luong_da_dung FROM tbl_phan_bo_ma_giam_gia WHERE user_id=? AND voucher_code=?",
                user.getId(), voucher.getCode())).isEqualTo(1);
        assertThat(count("SELECT COUNT(*) FROM tbl_su_dung_ma_giam_gia WHERE voucher_code=?", voucher.getCode()))
                .isEqualTo(1);
    }

    @Test
    void twoCustomersCannotClaimTheSameLastCampaignPlace() throws Exception {
        User first = customer(), second = customer();
        Voucher voucher = voucher();
        PromoHuntCampaign campaign = new PromoHuntCampaign();
        campaign.setId(id());
        campaign.setVoucherCode(voucher.getCode());
        campaign.setTotalQuantity(1);
        campaign.setStatus("ACTIVE");
        campaign.setStartAt(LocalDateTime.now().minusDays(1));
        campaign.setEndAt(LocalDateTime.now().plusDays(1));
        campaign.setCreatedAt(LocalDateTime.now());
        campaign.setUpdatedAt(LocalDateTime.now());
        campaigns.saveAndFlush(campaign);

        race(() -> promotions.claimCampaign(auth(first), campaign.getId()),
                () -> promotions.claimCampaign(auth(second), campaign.getId()), "da het");
        assertThat(count("SELECT COUNT(*) FROM tbl_luot_nhan_khuyen_mai WHERE campaign_id=?", campaign.getId()))
                .isEqualTo(1);
        assertThat(count("SELECT COALESCE(SUM(so_luong),0) FROM tbl_phan_bo_ma_giam_gia WHERE voucher_code=?",
                voucher.getCode())).isEqualTo(1);
    }

    @Test
    void invalidVoucherRollsBackReservedStockAndOrderParent() {
        User user = customer();
        Product product = product(1);
        assertThatThrownBy(() -> orders.createOrder(auth(user), request(product, "MISSING-" + id())))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("khong ton tai");
        assertThat(products.findById(product.getId()).orElseThrow().getTonKho()).isEqualTo(1);
        assertThat(count("SELECT COUNT(*) FROM tbl_don_hang WHERE user_id=?", user.getId())).isZero();
        assertThat(count("SELECT COUNT(*) FROM tbl_chi_tiet_don_hang WHERE product_id=?", product.getId())).isZero();
    }

    private void race(Supplier<?> first, Supplier<?> second, String rejection) throws Exception {
        CyclicBarrier start = new CyclicBarrier(2);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var left = executor.submit(attempt(start, first, rejection));
            var right = executor.submit(attempt(start, second, rejection));
            assertThat(List.of(left.get(25, TimeUnit.SECONDS), right.get(25, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }
    }

    private Callable<Boolean> attempt(CyclicBarrier start, Supplier<?> operation, String rejection) {
        return () -> {
            start.await(10, TimeUnit.SECONDS);
            TransactionTemplate tx = new TransactionTemplate(transactions);
            tx.setTimeout(15);
            try {
                return tx.execute(status -> {
                    // Bound contention failures on this test connection, without changing global MySQL settings.
                    Integer previous = jdbc.queryForObject("SELECT @@SESSION.innodb_lock_wait_timeout", Integer.class);
                    jdbc.execute("SET SESSION innodb_lock_wait_timeout = 5");
                    try {
                        operation.get();
                        return true;
                    } finally {
                        // Restore before this pooled connection can be used by another test.
                        jdbc.execute("SET SESSION innodb_lock_wait_timeout = " + previous);
                    }
                });
            } catch (BadRequestException expected) {
                assertThat(expected).hasMessageContaining(rejection);
                return false;
            }
        };
    }

    private User customer() {
        User user = new User();
        user.setId(id()); user.setUsername(id()); user.setPassword("unused-synthetic-fixture");
        user.setRole("CUSTOMER"); user.setHoTen("ASVS contention fixture");
        user.setEmail(id() + "@example.test"); user.setStatus("ACTIVE");
        user.setCreatedAt(LocalDateTime.now());
        return users.saveAndFlush(user);
    }

    private Product product(int stock) {
        Product product = new Product();
        product.setId(id()); product.setSku(id()); product.setTenSanPham("ASVS stock fixture");
        product.setDanhMuc("Fixture"); product.setGiaNhap(new BigDecimal("100000"));
        product.setGiaBan(new BigDecimal("200000")); product.setTonKho(stock);
        product.setTrangThai("ACTIVE"); product.setCreatedAt(LocalDateTime.now());
        return products.saveAndFlush(product);
    }

    private Voucher voucher() {
        Voucher voucher = new Voucher();
        voucher.setCode(id().toUpperCase(java.util.Locale.ROOT)); voucher.setLabel("ASVS voucher fixture");
        voucher.setDiscountPercent(new BigDecimal("0.10")); voucher.setMinimumOrder(BigDecimal.ZERO);
        voucher.setMaximumDiscount(new BigDecimal("100000")); voucher.setStatus("ACTIVE");
        voucher.setCreatedAt(LocalDateTime.now()); voucher.setUpdatedAt(LocalDateTime.now());
        return vouchers.saveAndFlush(voucher);
    }

    private OrderRequest request(Product product, String voucher) {
        return new OrderRequest(null, null, null, null, null, null, null, voucher, null,
                new OrderAddressPayload(null, "Fixture customer", "0901234567", "1 Fixture Road",
                        null, "Fixture Ward", null, "Fixture Province", null),
                List.of(new OrderItemPayload(product.getId(), null, null, null, null, null, null, 1, null, null)));
    }

    private long count(String sql, Object... args) { return jdbc.queryForObject(sql, Long.class, args); }
    private static String id() { return "asvs-race-" + UUID.randomUUID(); }
    private static UsernamePasswordAuthenticationToken auth(User user) {
        var principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
