package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.review.ProductReviewRequest;
import com.flarefitness.backend.dto.review.ProductReviewResponse;
import com.flarefitness.backend.dto.review.ProductReviewStatusRequest;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.entity.Order;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductReview;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.OrderItemRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductReviewRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import java.text.Normalizer;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.security.core.Authentication;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProductReviewService {

    private static final int LEGACY_LIST_LIMIT = 100;
    private static final String STATUS_VISIBLE = "Hi\u1ec3n th\u1ecb";
    private static final String STATUS_HIDDEN = "\u1ea8n";
    private static final List<String> REVIEWABLE_ORDER_STATUSES = List.of(
            "\u0110\u00e3 giao",
            "Ho\u00e0n t\u1ea5t",
            "Ho\u00e0n th\u00e0nh",
            "Delivered"
    );

    private final ProductReviewRepository productReviewRepository;
    private final ProductRepository productRepository;
    private final OrderRepository orderRepository;
    private final OrderItemRepository orderItemRepository;
    private final BehaviorAnalyticsService behaviorAnalyticsService;

    public ProductReviewService(
            ProductReviewRepository productReviewRepository,
            ProductRepository productRepository,
            OrderRepository orderRepository,
            OrderItemRepository orderItemRepository,
            BehaviorAnalyticsService behaviorAnalyticsService
    ) {
        this.productReviewRepository = productReviewRepository;
        this.productRepository = productRepository;
        this.orderRepository = orderRepository;
        this.orderItemRepository = orderItemRepository;
        this.behaviorAnalyticsService = behaviorAnalyticsService;
    }

    @Transactional(readOnly = true)
    public List<ProductReviewResponse> getVisibleReviewsByProduct(String productId) {
        return getVisibleReviewsByProductPage(productId, 0, LEGACY_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public List<ProductReviewResponse> getAllReviews() {
        return getAllReviewsPage(0, LEGACY_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public PageResponse<ProductReviewResponse> getVisibleReviewsByProductPage(String productId, Integer page, Integer size) {
        productRepository.findActiveById(productId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay san pham."));
        PageRequest pageable = pageRequest(page, size);
        return PageResponse.from(productReviewRepository
                .findByProductIdAndStatusOrderByCreatedAtDesc(productId, STATUS_VISIBLE, pageable)
                .map(this::toResponse));
    }

    @Transactional(readOnly = true)
    public PageResponse<ProductReviewResponse> getAllReviewsPage(Integer page, Integer size) {
        return PageResponse.from(productReviewRepository
                .findAllByOrderByCreatedAtDesc(pageRequest(page, size))
                .map(this::toResponse));
    }

    @Transactional
    public ProductReviewResponse createReview(ProductReviewRequest request, Authentication authentication) {
        User user = requireCustomer(authentication);
        Product product = productRepository.findActiveById(request.productId())
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay san pham."));

        Order deliveredOrder = resolveDeliveredOrderForReview(user, request.productId(), request.orderId());
        if (productReviewRepository.existsByUserIdAndProductIdAndOrderId(user.getId(), request.productId(), deliveredOrder.getId())) {
            throw new BadRequestException("Ban da danh gia san pham nay trong don hang nay.");
        }

        ProductReview review = new ProductReview();
        review.setId("review-" + UUID.randomUUID());
        review.setProductId(request.productId());
        review.setOrderId(deliveredOrder.getId());
        review.setUserId(user.getId());
        review.setReviewerName(firstNonBlank(user.getHoTen(), user.getUsername(), "Khach hang"));
        review.setRating(Math.min(5, Math.max(1, request.rating())));
        review.setContent(request.content().trim());
        review.setStatus(STATUS_VISIBLE);
        review.setCreatedAt(LocalDateTime.now());

        ProductReview savedReview = productReviewRepository.save(review);
        // A review is a verified action: unlike the browser analytics endpoint, it has already
        // passed ownership and delivered-order checks above.
        behaviorAnalyticsService.recordProductReview(user, savedReview, product);
        return toResponse(savedReview);
    }

    @Transactional
    public ProductReviewResponse updateStatus(String id, ProductReviewStatusRequest request) {
        ProductReview review = productReviewRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay danh gia."));
        review.setStatus(resolveStatus(request.status()));
        return toResponse(productReviewRepository.save(review));
    }

    @Transactional
    public void deleteReview(String id) {
        if (!productReviewRepository.existsById(id)) {
            throw new ResourceNotFoundException("Khong tim thay danh gia.");
        }
        productReviewRepository.deleteById(id);
    }

    private Order resolveDeliveredOrderForReview(User user, String productId, String requestedOrderId) {
        String normalizedOrderId = trimToNull(requestedOrderId);
        if (normalizedOrderId != null) {
            Order order = orderRepository.findById(normalizedOrderId)
                    .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay don hang."));
            validateReviewableOrder(user, order, productId);
            return order;
        }

        List<Order> deliveredOrders = productReviewRepository.findFirstReviewableOrderForProduct(
                user.getId(),
                productId,
                REVIEWABLE_ORDER_STATUSES,
                PageRequest.of(0, 1)
        );
        if (deliveredOrders.isEmpty()) {
            throw new BadRequestException("Khong co don hang da giao nao con duoc danh gia cho san pham nay.");
        }

        return deliveredOrders.get(0);
    }

    private void validateReviewableOrder(User user, Order order, String productId) {
        if (!String.valueOf(order.getUserId()).equals(String.valueOf(user.getId()))) {
            throw new UnauthorizedException("Ban khong co quyen danh gia san pham trong don hang nay.");
        }
        if (!isDeliveredStatus(order.getTrangThaiDon())) {
            throw new BadRequestException("Chi co the danh gia san pham trong don hang da giao.");
        }
        if (!orderItemRepository.existsByOrderIdAndProductId(order.getId(), productId)) {
            throw new BadRequestException("San pham khong thuoc don hang nay.");
        }
    }

    private boolean isDeliveredStatus(String status) {
        String normalized = normalize(status);
        return normalized.contains("da giao")
                || normalized.contains("hoan tat")
                || normalized.contains("hoan thanh")
                || normalized.contains("delivered");
    }

    private String resolveStatus(String status) {
        String normalized = normalize(status);
        if (normalized.contains("an") || normalized.contains("hidden")) {
            return STATUS_HIDDEN;
        }
        if (normalized.contains("hien thi") || normalized.contains("visible") || normalized.contains("active")) {
            return STATUS_VISIBLE;
        }
        throw new BadRequestException("Trang thai danh gia khong hop le.");
    }

    private ProductReviewResponse toResponse(ProductReview review) {
        return new ProductReviewResponse(
                review.getId(),
                review.getProductId(),
                review.getOrderId(),
                review.getUserId(),
                review.getReviewerName(),
                review.getRating(),
                review.getContent(),
                review.getStatus(),
                review.getCreatedAt()
        );
    }

    private User requireCustomer(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new UnauthorizedException("Phien dang nhap khong hop le.");
        }

        User user = principal.getUser();
        String authority = CurrentUserPrincipal.toAuthority(user.getRole());
        if ("ROLE_ADMIN".equals(authority) || "ROLE_STAFF".equals(authority)) {
            throw new UnauthorizedException("Chuc nang danh gia chi danh cho khach hang.");
        }
        return user;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "Khach hang";
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private String normalize(String value) {
        return Normalizer.normalize(String.valueOf(value == null ? "" : value), Normalizer.Form.NFD)
                .replaceAll("\\p{M}+", "")
                .toLowerCase(Locale.ROOT)
                .replace('\u0111', 'd')
                .replace('\u0110', 'd')
                .replaceAll("[^a-z0-9\\s-]", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private PageRequest pageRequest(Integer page, Integer size) {
        int safePage = Math.max(page == null ? 0 : page, 0);
        int safeSize = Math.min(Math.max(size == null ? 20 : size, 1), 100);
        return PageRequest.of(safePage, safeSize);
    }
}
