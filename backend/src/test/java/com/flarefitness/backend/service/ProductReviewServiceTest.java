package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.entity.ProductReview;
import com.flarefitness.backend.repository.OrderItemRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductReviewRepository;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

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
