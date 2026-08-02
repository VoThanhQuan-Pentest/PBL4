package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.review.ProductReviewRequest;
import com.flarefitness.backend.entity.Order;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductReview;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.OrderItemRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductReviewRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class ProductReviewServiceTest {

    @Mock private ProductReviewRepository productReviewRepository;
    @Mock private ProductRepository productRepository;
    @Mock private OrderRepository orderRepository;
    @Mock private OrderItemRepository orderItemRepository;
    @Mock private BehaviorAnalyticsService behaviorAnalyticsService;

    private ProductReviewService productReviewService;

    @BeforeEach
    void setUp() {
        productReviewService = new ProductReviewService(
                productReviewRepository,
                productRepository,
                orderRepository,
                orderItemRepository,
                behaviorAnalyticsService);
    }

    @Test
    void legacyReviewListUsesTheFirstBoundedPage() {
        ProductReview review = review();
        when(productReviewRepository.findAllByOrderByCreatedAtDesc(org.mockito.ArgumentMatchers.any(Pageable.class)))
                .thenAnswer(invocation -> {
                    Pageable pageable = invocation.getArgument(0);
                    return new PageImpl<>(List.of(review), pageable, 101);
                });

        var reviews = productReviewService.getAllReviews();

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(productReviewRepository).findAllByOrderByCreatedAtDesc(pageable.capture());
        assertThat(pageable.getValue().getPageNumber()).isZero();
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
        assertThat(reviews).extracting(item -> item.id()).containsExactly("review-1");
    }

    @Test
    void publicProductReviewsMapOnlyPublicFields() {
        ProductReview review = review();
        Product product = new Product();
        product.setId("product-1");
        when(productRepository.findActiveById(product.getId())).thenReturn(Optional.of(product));
        when(productReviewRepository.findByProductIdAndStatusOrderByCreatedAtDesc(
                org.mockito.ArgumentMatchers.eq(product.getId()),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(review)));

        var reviews = productReviewService.getVisibleReviewsByProduct(product.getId());

        assertThat(reviews).singleElement().satisfies(item -> {
            assertThat(item.id()).isEqualTo("review-1");
            assertThat(item.productId()).isEqualTo("product-1");
            assertThat(item.reviewer()).isEqualTo("Page Test");
            assertThat(item.content()).isEqualTo("Good");
        });
    }

    @Test
    void authenticatedStaffReviewAttemptIsAccessDeniedWhileMissingAuthenticationIsUnauthorized() {
        Authentication staffAuthentication = authentication(user("staff-1", "staff"));
        ProductReviewRequest request = new ProductReviewRequest(
                "product-1", "order-1", 5, "San pham rat tot");

        assertThatThrownBy(() -> productReviewService.createReview(request, staffAuthentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("chi danh cho khach hang");

        assertThatThrownBy(() -> productReviewService.createReview(request, null))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Phien dang nhap");
    }

    @Test
    void reviewOfAnotherCustomersOrderIsAccessDenied() {
        User customer = user("user-1", "customer");
        Product product = new Product();
        product.setId("product-1");
        Order order = new Order();
        order.setId("order-1");
        order.setUserId("user-2");
        when(productRepository.findActiveById(product.getId())).thenReturn(Optional.of(product));
        when(orderRepository.findById(order.getId())).thenReturn(Optional.of(order));

        ProductReviewRequest request = new ProductReviewRequest(
                product.getId(), order.getId(), 5, "San pham rat tot");

        assertThatThrownBy(() -> productReviewService.createReview(request, authentication(customer)))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("khong co quyen");
    }

    private User user(String id, String role) {
        User user = new User();
        user.setId(id);
        user.setUsername(id);
        user.setPassword("password");
        user.setRole(role);
        user.setStatus("ACTIVE");
        user.setDeleted(false);
        return user;
    }

    private Authentication authentication(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    private ProductReview review() {
        ProductReview review = new ProductReview();
        review.setId("review-1");
        review.setProductId("product-1");
        review.setOrderId("order-1");
        review.setUserId("user-1");
        review.setReviewerName("Page Test");
        review.setRating(5);
        review.setContent("Good");
        review.setStatus("Hiển thị");
        review.setCreatedAt(LocalDateTime.now());
        return review;
    }
}
