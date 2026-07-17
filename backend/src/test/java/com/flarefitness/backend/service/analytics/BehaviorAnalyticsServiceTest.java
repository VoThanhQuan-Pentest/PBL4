package com.flarefitness.backend.service.analytics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.analytics.AdminBehaviorAnalyticsResponse;
import com.flarefitness.backend.dto.analytics.BehaviorEventType;
import com.flarefitness.backend.dto.analytics.BehaviorPageType;
import com.flarefitness.backend.dto.analytics.TrackBehaviorEventRequest;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.analytics.UserBehaviorEvent;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.analytics.UserBehaviorEventRepository;
import com.flarefitness.backend.repository.analytics.UserBehaviorProfileRepository;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.redis.core.StringRedisTemplate;

@ExtendWith(MockitoExtension.class)
class BehaviorAnalyticsServiceTest {

    @Mock
    private UserBehaviorEventRepository eventRepository;
    @Mock
    private UserBehaviorProfileRepository profileRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ProductRepository productRepository;
    @Mock
    private OrderRepository orderRepository;
    @Mock
    private StringRedisTemplate redisTemplate;

    private BehaviorAnalyticsService service;

    @BeforeEach
    void setUp() {
        service = new BehaviorAnalyticsService(
                eventRepository,
                profileRepository,
                userRepository,
                productRepository,
                orderRepository,
                new ObjectMapper(),
                redisTemplate,
                "cache:recommendation:",
                "cache:recommendation:popularity",
                900,
                300);
    }

    @Test
    void publicProductEventUsesCatalogFieldsAndIgnoresSpoofedAnalyticsFields() {
        Product product = product("product-1", "World Cup Shirt", "Football", "Adidas", "500000");
        when(productRepository.findActiveById(product.getId())).thenReturn(Optional.of(product));
        AtomicReference<UserBehaviorEvent> saved = new AtomicReference<>();
        when(eventRepository.save(any(UserBehaviorEvent.class))).thenAnswer(invocation -> {
            UserBehaviorEvent event = invocation.getArgument(0);
            saved.set(event);
            return event;
        });

        service.trackEvent(new TrackBehaviorEventRequest(
                "client-controlled-session",
                BehaviorEventType.PRODUCT_VIEW,
                BehaviorPageType.PRODUCT_DETAIL,
                "client-page-key",
                product.getId(),
                "forged-order",
                "Forged category",
                "Forged brand",
                "ignore me",
                new BigDecimal("1.00"),
                10,
                null,
                java.util.Map.of("email", "not-for-analytics@example.com")), null,
                "analytics-123e4567-e89b-12d3-a456-426614174000");

        assertThat(saved.get()).isNotNull();
        assertThat(saved.get().getSessionId()).isEqualTo("analytics-123e4567-e89b-12d3-a456-426614174000");
        assertThat(saved.get().getProductId()).isEqualTo(product.getId());
        assertThat(saved.get().getCategoryKey()).isEqualTo("Football");
        assertThat(saved.get().getBrandKey()).isEqualTo("Adidas");
        assertThat(saved.get().getPriceValue()).isEqualByComparingTo("500000");
        assertThat(saved.get().getOrderId()).isNull();
        assertThat(saved.get().getQuantity()).isNull();
        assertThat(saved.get().getMetadataJson()).isNull();
        assertThat(saved.get().getPageKey()).isEqualTo(product.getSku());
    }

    @Test
    void publicPurchaseAndReviewEventsAreRejectedBeforePersistence() {
        TrackBehaviorEventRequest purchase = new TrackBehaviorEventRequest(
                null, BehaviorEventType.PURCHASE, null, null, null, "order-1", null,
                null, null, null, null, null, null);
        TrackBehaviorEventRequest review = new TrackBehaviorEventRequest(
                null, BehaviorEventType.PRODUCT_REVIEW, null, null, null, null, null,
                null, null, null, null, null, null);

        assertThatThrownBy(() -> service.trackEvent(purchase, null, "analytics-123e4567-e89b-12d3-a456-426614174000"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.trackEvent(review, null, "analytics-123e4567-e89b-12d3-a456-426614174000"))
                .isInstanceOf(BadRequestException.class);

        verify(eventRepository, never()).save(any(UserBehaviorEvent.class));
    }

    @Test
    void recommendationReadsUseBoundedTrustedEventsAndCatalogCandidates() {
        Product product = product("product-1", "World Cup Shirt", "Football", "Adidas", "500000");
        ArgumentCaptor<Pageable> popularityPageable = ArgumentCaptor.forClass(Pageable.class);
        ArgumentCaptor<Pageable> catalogPageable = ArgumentCaptor.forClass(Pageable.class);
        when(eventRepository.findTrustedByCreatedAtAfterOrderByCreatedAtDesc(
                any(LocalDateTime.class), any(Pageable.class))).thenReturn(List.of());
        when(productRepository.findAllByOrderByCreatedAtDesc(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(product)));

        service.getRecommendations(null, null, "home", null, List.of(), 1);

        verify(eventRepository).findTrustedByCreatedAtAfterOrderByCreatedAtDesc(
                any(LocalDateTime.class), popularityPageable.capture());
        verify(productRepository).findAllByOrderByCreatedAtDesc(catalogPageable.capture());
        assertThat(popularityPageable.getValue().getPageSize()).isEqualTo(1500);
        assertThat(catalogPageable.getValue().getPageSize()).isEqualTo(1000);
    }

    @Test
    void adminOverviewUsesBoundedDatabaseAggregatesInsteadOfLoadingRawEvents() {
        when(eventRepository.countByEventTypeBetween(any(LocalDateTime.class), any(LocalDateTime.class))).thenReturn(List.of(
                eventCount(BehaviorEventType.PRODUCT_VIEW, 10),
                eventCount(BehaviorEventType.PRODUCT_SEARCH, 4),
                eventCount(BehaviorEventType.ADD_TO_CART, 3),
                eventCount(BehaviorEventType.PURCHASE, 2),
                eventCount(BehaviorEventType.PRODUCT_REVIEW, 1)));
        when(eventRepository.countDistinctAuthenticatedUsersBetween(any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(5L);
        when(eventRepository.averagePageStaySecondsBetween(any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(31.6D);
        when(eventRepository.findTopProductMetricsBetween(
                any(LocalDateTime.class), any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(metric("product-1", 24L)));
        when(eventRepository.findTopCategoryMetricsBetween(
                any(LocalDateTime.class), any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(metric("Football", 18L)));
        when(eventRepository.findTopPriceBucketMetricsBetween(
                any(LocalDateTime.class), any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(metric("500K_1M", 18L)));
        when(eventRepository.findTopSearchKeywordMetricsBetween(
                any(LocalDateTime.class), any(LocalDateTime.class), any(Pageable.class)))
                .thenReturn(List.of(metric("world cup", 8L)));
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of(
                product("product-1", "World Cup Shirt", "Football", "Adidas", "500000")));
        when(orderRepository.sumPaidRevenueBetween(any(LocalDate.class), any(LocalDate.class)))
                .thenReturn(new BigDecimal("1234500"));

        AdminBehaviorAnalyticsResponse response = service.getAdminAnalytics(
                LocalDate.of(2026, 1, 1), LocalDate.of(2026, 1, 31));

        assertThat(response.totalEvents()).isEqualTo(20);
        assertThat(response.uniqueUsers()).isEqualTo(5);
        assertThat(response.averageStaySeconds()).isEqualTo(32);
        assertThat(response.topProducts()).singleElement().satisfies(metric -> {
            assertThat(metric.key()).isEqualTo("product-1");
            assertThat(metric.label()).isEqualTo("World Cup Shirt");
            assertThat(metric.score()).isEqualTo(24);
        });
        assertThat(response.topKeywords()).extracting(metric -> metric.key())
                .containsExactlyInAnyOrder("world", "cup");
        assertThat(response.topKeywords()).allSatisfy(metric -> assertThat(metric.score()).isEqualTo(8));
        verify(eventRepository, never()).findByCreatedAtBetween(any(LocalDateTime.class), any(LocalDateTime.class));
    }

    private Product product(String id, String name, String category, String brand, String price) {
        Product product = new Product();
        product.setId(id);
        product.setTenSanPham(name);
        product.setSku("SKU-" + id);
        product.setDanhMuc(category);
        product.setThuongHieu(brand);
        product.setGiaBan(new BigDecimal(price));
        product.setTonKho(10);
        product.setDeleted(false);
        return product;
    }

    private UserBehaviorEventRepository.EventTypeCount eventCount(BehaviorEventType eventType, long count) {
        return new UserBehaviorEventRepository.EventTypeCount() {
            @Override
            public BehaviorEventType getEventType() {
                return eventType;
            }

            @Override
            public long getEventCount() {
                return count;
            }
        };
    }

    private UserBehaviorEventRepository.MetricValue metric(String key, long score) {
        return new UserBehaviorEventRepository.MetricValue() {
            @Override
            public String getMetricKey() {
                return key;
            }

            @Override
            public Long getScore() {
                return score;
            }
        };
    }
}
