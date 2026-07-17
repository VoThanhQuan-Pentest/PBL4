package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.dto.analytics.BehaviorEventType;
import com.flarefitness.backend.dto.analytics.BehaviorPageType;
import com.flarefitness.backend.dto.analytics.TrackBehaviorEventRequest;
import com.flarefitness.backend.dto.support.SupportThreadResponse;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.support.SupportMessage;
import com.flarefitness.backend.entity.support.SupportThread;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.support.SupportMessageRepository;
import com.flarefitness.backend.repository.support.SupportThreadRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import com.flarefitness.backend.service.support.SupportChatService;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@SpringBootTest
class AnalyticsAndSupportIntegrationTest extends ContainerizedIntegrationTest {

    @Autowired private BehaviorAnalyticsService behaviorAnalyticsService;
    @Autowired private SupportChatService supportChatService;
    @Autowired private ProductRepository productRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private SupportThreadRepository supportThreadRepository;
    @Autowired private SupportMessageRepository supportMessageRepository;

    @Test
    void adminAnalyticsRunsDatabaseAggregateQueriesAgainstMySql() {
        String suffix = suffix();
        Product product = product("analytics-product-" + suffix, suffix);
        productRepository.save(product);
        User customer = user("analytics-customer-" + suffix, "analytics_" + suffix, "CUSTOMER");
        userRepository.save(customer);

        behaviorAnalyticsService.trackEvent(new TrackBehaviorEventRequest(
                "ignored-client-session",
                BehaviorEventType.PRODUCT_VIEW,
                BehaviorPageType.PRODUCT_DETAIL,
                "ignored-page-key",
                product.getId(),
                "ignored-order",
                "forged-category",
                "forged-brand",
                null,
                BigDecimal.ONE,
                1,
                null,
                null), authentication(customer), "analytics-" + UUID.randomUUID());

        var overview = behaviorAnalyticsService.getAdminAnalytics(LocalDate.now(), LocalDate.now());

        assertThat(overview.totalEvents()).isGreaterThanOrEqualTo(1);
        assertThat(overview.topProducts()).anySatisfy(metric -> {
            assertThat(metric.key()).isEqualTo(product.getId());
            assertThat(metric.label()).isEqualTo(product.getTenSanPham());
        });
        assertThat(overview.topCategories()).anySatisfy(metric -> assertThat(metric.key()).isEqualTo("Analytics"));
    }

    @Test
    void workspaceUsesOneBoundedNativeMessageQueryPerPage() {
        String suffix = suffix();
        User staff = user("support-staff-" + suffix, "staff_" + suffix, "STAFF");
        User customer = user("support-customer-" + suffix, "customer_" + suffix, "CUSTOMER");
        userRepository.saveAll(List.of(staff, customer));

        SupportThread thread = new SupportThread();
        thread.setId("support-thread-" + suffix);
        thread.setCustomerUserId(customer.getId());
        thread.setStatus("Đang mở");
        thread.setCreatedAt(LocalDateTime.now().minusMinutes(60));
        thread.setUpdatedAt(LocalDateTime.now());
        supportThreadRepository.save(thread);

        LocalDateTime baseTime = LocalDateTime.now().minusMinutes(55);
        for (int index = 0; index < 55; index++) {
            SupportMessage message = new SupportMessage();
            message.setId("support-message-" + suffix + "-" + index);
            message.setThreadId(thread.getId());
            message.setSenderType(index % 2 == 0 ? "customer" : "staff");
            message.setSenderUserId(index % 2 == 0 ? customer.getId() : staff.getId());
            message.setText("message " + index);
            message.setCreatedAt(baseTime.plusMinutes(index));
            supportMessageRepository.save(message);
        }

        List<SupportThreadResponse> threads = supportChatService.getThreadsForWorkspace(authentication(staff));

        SupportThreadResponse response = threads.stream()
                .filter(item -> thread.getId().equals(item.id()))
                .findFirst()
                .orElseThrow();
        assertThat(response.messages()).hasSize(50);
        assertThat(response.messages().get(0).text()).isEqualTo("message 5");
        assertThat(response.messages().get(response.messages().size() - 1).text()).isEqualTo("message 54");
    }

    private Product product(String id, String suffix) {
        Product product = new Product();
        product.setId(id);
        product.setSku("AN-" + suffix);
        product.setTenSanPham("Analytics Product " + suffix);
        product.setDanhMuc("Analytics");
        product.setThuongHieu("Flare");
        product.setGiaNhap(new BigDecimal("100000"));
        product.setGiaBan(new BigDecimal("500000"));
        product.setTonKho(10);
        product.setTrangThai("Dang ban");
        product.setDeleted(false);
        product.setCreatedAt(LocalDateTime.now());
        return product;
    }

    private User user(String id, String username, String role) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setPassword("$2a$12$Z8xXRjkmASDQSZXYwYEwZOqBzW7WSTl4YpJrB2O2A1s2dWmQWdd5S");
        user.setRole(role);
        user.setHoTen(username);
        user.setEmail(username + "@example.test");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());
        return user;
    }

    private Authentication authentication(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    private String suffix() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }
}
