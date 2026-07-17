package com.flarefitness.backend.service.analytics;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.analytics.AdminBehaviorAnalyticsResponse;
import com.flarefitness.backend.dto.analytics.BehaviorEventResponse;
import com.flarefitness.backend.dto.analytics.BehaviorEventType;
import com.flarefitness.backend.dto.analytics.NamedMetricResponse;
import com.flarefitness.backend.dto.analytics.TrackBehaviorEventRequest;
import com.flarefitness.backend.dto.analytics.UserBehaviorInsightResponse;
import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductReview;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.analytics.UserBehaviorEvent;
import com.flarefitness.backend.entity.analytics.UserBehaviorProfile;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.analytics.UserBehaviorEventRepository;
import com.flarefitness.backend.repository.analytics.UserBehaviorProfileRepository;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class BehaviorAnalyticsService {

    private static final int PROFILE_EVENT_LOOKBACK = 300;
    private static final int POPULARITY_LOOKBACK_EVENTS = 1500;
    private static final int DEFAULT_RECOMMENDATION_LIMIT = 8;
    private static final int DEFAULT_TOP_ITEMS_LIMIT = 8;
    private static final int DEFAULT_PROFILE_TOP_LIMIT = 5;
    private static final int ADMIN_KEYWORD_CANDIDATE_LIMIT = 200;
    private static final int RECOMMENDATION_CANDIDATE_LIMIT = 1000;
    private static final int MAX_TRACKED_PAGE_STAY_SECONDS = 300;
    private static final Duration BEHAVIOR_RECALCULATION_INTERVAL = Duration.ofHours(2);

    private final UserBehaviorEventRepository eventRepository;
    private final UserBehaviorProfileRepository profileRepository;
    private final UserRepository userRepository;
    private final ProductRepository productRepository;
    private final OrderRepository orderRepository;
    private final ObjectMapper objectMapper;
    private final StringRedisTemplate redisTemplate;
    private final String recommendationCachePrefix;
    private final String popularityCacheKey;
    private final Duration recommendationCacheTtl;
    private final Duration popularityCacheTtl;

    public BehaviorAnalyticsService(
            UserBehaviorEventRepository eventRepository,
            UserBehaviorProfileRepository profileRepository,
            UserRepository userRepository,
            ProductRepository productRepository,
            OrderRepository orderRepository,
            ObjectMapper objectMapper,
            StringRedisTemplate redisTemplate,
            @Value("${app.cache.recommendation-prefix}") String recommendationCachePrefix,
            @Value("${app.cache.recommendation-popularity-key}") String popularityCacheKey,
            @Value("${app.cache.recommendation-ttl-seconds}") long recommendationCacheTtlSeconds,
            @Value("${app.cache.recommendation-popularity-ttl-seconds}") long popularityCacheTtlSeconds) {
        // Ghi nhận các sự kiện hành vi người dùng
        this.eventRepository = eventRepository;
        this.profileRepository = profileRepository;
        this.userRepository = userRepository;
        this.productRepository = productRepository;
        this.orderRepository = orderRepository;
        this.objectMapper = objectMapper;
        this.redisTemplate = redisTemplate;
        this.recommendationCachePrefix = recommendationCachePrefix;
        this.popularityCacheKey = popularityCacheKey;
        this.recommendationCacheTtl = Duration.ofSeconds(recommendationCacheTtlSeconds);
        this.popularityCacheTtl = Duration.ofSeconds(popularityCacheTtlSeconds);
    }

    @Transactional
    public BehaviorEventResponse trackEvent(TrackBehaviorEventRequest request, Authentication authentication) {
        return trackEvent(request, authentication, "guest-" + UUID.randomUUID());
    }

    /**
     * Records a browser event using a server-issued session id.  The request's session, product
     * metadata, price, order id, and quantity are deliberately not trusted.
     */
    @Transactional
    public BehaviorEventResponse trackEvent(
            TrackBehaviorEventRequest request,
            Authentication authentication,
            String trustedSessionId) {
        String userId = resolveUserId(authentication);
        CanonicalPublicEvent canonicalEvent = canonicalizePublicEvent(request, userId);
        String sessionId = normalizeTrustedSessionId(trustedSessionId);

        UserBehaviorEvent event = new UserBehaviorEvent();
        event.setId(UUID.randomUUID().toString());
        event.setCreatedAt(LocalDateTime.now());
        event.setUserId(userId);
        event.setSessionId(sessionId);
        event.setEventType(request.eventType());
        event.setPageType(request.pageType());
        event.setPageKey(canonicalEvent.pageKey());
        event.setProductId(canonicalEvent.productId());
        // Order IDs, prices, quantities, and arbitrary metadata from public browsers must not be
        // allowed to influence reporting.  Purchases and reviews are written by server flows below.
        event.setOrderId(null);
        event.setCategoryKey(canonicalEvent.categoryKey());
        event.setBrandKey(canonicalEvent.brandKey());
        event.setSearchKeyword(canonicalEvent.searchKeyword());
        event.setPriceValue(canonicalEvent.priceValue());
        event.setPriceBucket(resolvePriceBucket(canonicalEvent.priceValue()));
        event.setQuantity(canonicalEvent.quantity());
        event.setDurationSeconds(canonicalEvent.durationSeconds());
        event.setMetadataJson(null);
        eventRepository.save(event);

        rebuildUserProfileIfDue(userId, event.getCreatedAt());

        return new BehaviorEventResponse("RECORDED", sessionId, event.getCreatedAt());
    }

    public void recordPurchase(User user, com.flarefitness.backend.entity.Order order,
            List<com.flarefitness.backend.entity.OrderItem> items) {
        LocalDateTime now = LocalDateTime.now();
        Map<String, Product> productsById = productRepository.findAllById(items.stream()
                        .map(com.flarefitness.backend.entity.OrderItem::getProductId)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet()))
                .stream()
                .collect(Collectors.toMap(Product::getId, Function.identity(), (left, right) -> left));
        for (com.flarefitness.backend.entity.OrderItem item : items) {
            Product product = productsById.get(item.getProductId());
            UserBehaviorEvent event = new UserBehaviorEvent();
            event.setId(UUID.randomUUID().toString());
            event.setCreatedAt(now);
            event.setUserId(user.getId());
            event.setSessionId("order:" + order.getId());
            event.setEventType(BehaviorEventType.PURCHASE);
            event.setProductId(item.getProductId());
            event.setOrderId(order.getId());
            event.setCategoryKey(product != null ? cleanKey(product.getDanhMuc()) : null);
            event.setBrandKey(product != null ? cleanKey(product.getThuongHieu()) : null);
            event.setPriceValue(item.getDonGia());
            event.setPriceBucket(resolvePriceBucket(item.getDonGia()));
            event.setQuantity(item.getSoLuong());
            eventRepository.save(event);
        }
        rebuildUserProfileIfDue(user.getId(), now);
    }

    @Transactional
    public void recordProductReview(User user, ProductReview review, Product product) {
        if (user == null || review == null || product == null) {
            return;
        }

        LocalDateTime createdAt = review.getCreatedAt() != null ? review.getCreatedAt() : LocalDateTime.now();
        UserBehaviorEvent event = new UserBehaviorEvent();
        event.setId(UUID.randomUUID().toString());
        event.setCreatedAt(createdAt);
        event.setUserId(user.getId());
        event.setSessionId("review:" + review.getId());
        event.setEventType(BehaviorEventType.PRODUCT_REVIEW);
        event.setProductId(product.getId());
        event.setOrderId(review.getOrderId());
        event.setCategoryKey(cleanKey(product.getDanhMuc()));
        event.setBrandKey(cleanKey(product.getThuongHieu()));
        event.setPriceValue(product.getGiaBan());
        event.setPriceBucket(resolvePriceBucket(product.getGiaBan()));
        event.setQuantity(1);
        eventRepository.save(event);
        rebuildUserProfileIfDue(user.getId(), createdAt);
    }

    @Transactional
    public UserBehaviorInsightResponse getCurrentUserInsights(Authentication authentication) {
        String userId = requireUserId(authentication);
        UserBehaviorProfile profile = profileRepository.findById(userId).orElse(null);
        if (profile == null) {
            profile = rebuildUserProfile(userId);
        }
        return toInsightResponse(profile);
    }

    @Transactional
    public UserBehaviorProfile rebuildUserProfile(String userId) {
        List<UserBehaviorEvent> recentEvents = eventRepository.findTop300ByUserIdOrderByCreatedAtDesc(userId);
        BehaviorSnapshot snapshot = buildSnapshot(recentEvents);

        UserBehaviorProfile profile = profileRepository.findById(userId).orElseGet(UserBehaviorProfile::new);
        LocalDateTime now = LocalDateTime.now();
        if (profile.getCreatedAt() == null) {
            profile.setCreatedAt(now);
        }

        profile.setUserId(userId);
        profile.setFavoriteCategory(snapshot.favoriteCategory());
        profile.setFavoriteBrand(snapshot.favoriteBrand());
        profile.setPreferredPriceBucket(snapshot.preferredPriceBucket());
        profile.setPriceMin(snapshot.priceMin());
        profile.setPriceMax(snapshot.priceMax());
        profile.setTopCategoriesJson(writeJson(snapshot.topCategories()));
        profile.setTopBrandsJson(writeJson(snapshot.topBrands()));
        profile.setTopKeywordsJson(writeJson(snapshot.topKeywords()));
        profile.setLastViewedProductId(snapshot.lastViewedProductId());
        profile.setTotalInteractions(snapshot.totalInteractions());
        profile.setAverageStaySeconds(snapshot.averageStaySeconds());
        profile.setTotalPurchases(snapshot.totalPurchases());
        profile.setUpdatedAt(now);

        return profileRepository.save(profile);
    }

    private void rebuildUserProfileIfDue(String userId, LocalDateTime now) {
        String safeUserId = trimToNull(userId);
        if (safeUserId == null) {
            return;
        }

        LocalDateTime threshold = (now != null ? now : LocalDateTime.now()).minus(BEHAVIOR_RECALCULATION_INTERVAL);
        UserBehaviorProfile profile = profileRepository.findById(safeUserId).orElse(null);
        if (profile == null || profile.getUpdatedAt() == null || profile.getUpdatedAt().isBefore(threshold)) {
            rebuildUserProfile(safeUserId);
        }
    }

    @Transactional(readOnly = true)
    public List<ProductResponse> getRecommendations(
            Authentication authentication,
            String sessionId,
            String context,
            String productId,
            List<String> productIds,
            Integer limit) {
        int safeLimit = Math.min(Math.max(limit == null ? DEFAULT_RECOMMENDATION_LIMIT : limit, 1), 16);
        String userId = resolveUserId(authentication);
        String normalizedSessionId = trimToNull(sessionId);
        String normalizedContext = trimToNull(context) != null ? trimToNull(context).toLowerCase(Locale.ROOT) : "home";
        String cacheKey = buildRecommendationCacheKey(userId, normalizedSessionId, normalizedContext, productId,
                productIds, safeLimit);
        List<ProductResponse> cachedRecommendations = readRecommendationCache(cacheKey);
        if (cachedRecommendations != null) {
            return cachedRecommendations;
        }

        LocalDateTime now = LocalDateTime.now();
        BehaviorSnapshot snapshot = userId != null
                ? buildSnapshot(eventRepository.findTop300ByUserIdOrderByCreatedAtDesc(userId))
                : buildSnapshot(normalizedSessionId == null
                        ? List.of()
                        : eventRepository.findTop300BySessionIdOrderByCreatedAtDesc(normalizedSessionId));

        Map<String, Long> popularityScores = getPopularityScores(now);

        // Recommendations only ever return 16 products. Keep the candidate set
        // bounded as well so a large catalog cannot turn this request into an
        // unbounded database read and JVM allocation.
        List<Product> products = productRepository
                .findAllByOrderByCreatedAtDesc(PageRequest.of(0, RECOMMENDATION_CANDIDATE_LIMIT))
                .getContent();
        Map<String, Product> productIndex = products.stream()
                .collect(Collectors.toMap(Product::getId, Function.identity(), (left, right) -> left,
                        LinkedHashMap::new));

        Product contextProduct = productIndex.get(trimToNull(productId));
        Set<String> excludedIds = new LinkedHashSet<>();
        if (contextProduct != null) {
            excludedIds.add(contextProduct.getId());
        }
        if (productIds != null) {
            productIds.stream()
                    .map(this::trimToNull)
                    .filter(Objects::nonNull)
                    .forEach(excludedIds::add);
        }

        List<Product> cartProducts = "cart".equals(normalizedContext) && productIds != null
                ? productIds.stream()
                        .map(productIndex::get)
                        .filter(Objects::nonNull)
                        .toList()
                : List.of();
        Map<String, Long> cartCategoryCounts = cartProducts.stream()
                .map(product -> cleanKey(product.getDanhMuc()))
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
        Map<String, Long> cartBrandCounts = cartProducts.stream()
                .map(product -> cleanKey(product.getThuongHieu()))
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
        Comparator<ProductScore> worstFirst = Comparator.comparingLong(ProductScore::score)
                .thenComparing(item -> item.product().getCreatedAt(), Comparator.nullsFirst(Comparator.naturalOrder()));
        PriorityQueue<ProductScore> topProducts = new PriorityQueue<>(safeLimit, worstFirst);

        for (Product product : products) {
            if (product == null || product.getTonKho() == null || product.getTonKho() <= 0) {
                continue;
            }
            if (excludedIds.contains(product.getId())) {
                continue;
            }
            // Tính điểm đề xuất
            long score = popularityScores.getOrDefault(product.getId(), 0L);
            score += snapshot.categoryScores().getOrDefault(cleanKey(product.getDanhMuc()), 0L) * 5;
            score += snapshot.brandScores().getOrDefault(cleanKey(product.getThuongHieu()), 0L) * 4;
            score += snapshot.priceBucketScores().getOrDefault(resolvePriceBucket(product.getGiaBan()), 0L) * 3;

            // Nếu ở trong trang chi tiết của sản phẩm
            if ("detail".equals(normalizedContext) && contextProduct != null) {
                if (sameIgnoreCase(product.getDanhMuc(), contextProduct.getDanhMuc())) {
                    score += 40;
                }
                if (sameIgnoreCase(product.getThuongHieu(), contextProduct.getThuongHieu())) {
                    score += 18;
                }
            }

            // Nếu sản phẩm đang ở giỏ hàng
            if (!cartCategoryCounts.isEmpty() || !cartBrandCounts.isEmpty()) {
                score += cartCategoryCounts.getOrDefault(cleanKey(product.getDanhMuc()), 0L) * 18;
                score += cartBrandCounts.getOrDefault(cleanKey(product.getThuongHieu()), 0L) * 8;
            }

            // Nếu sản phẩm ở danh mục yêu thích
            if ("home".equals(normalizedContext) && sameIgnoreCase(product.getDanhMuc(), snapshot.favoriteCategory())) {
                score += 24;
            }

            if (score > 0) {
                ProductScore candidate = new ProductScore(product, score);
                if (topProducts.size() < safeLimit) {
                    topProducts.offer(candidate);
                } else if (worstFirst.compare(candidate, topProducts.peek()) > 0) {
                    topProducts.poll();
                    topProducts.offer(candidate);
                }
            }
        }
        // Sắp xếp danh sách giảm dần và trả vêf
        List<ProductResponse> recommendations = topProducts.stream()
                .sorted(worstFirst.reversed())
                .map(ProductScore::product)
                .map(this::toProductResponse)
                .toList();
        cacheRecommendations(cacheKey, recommendations);
        return recommendations;
    }

    @Transactional(readOnly = true)
    public AdminBehaviorAnalyticsResponse getAdminAnalytics(LocalDate fromDate, LocalDate toDate) {
        LocalDate today = LocalDate.now();
        LocalDate safeFrom = fromDate != null ? fromDate : today.minusDays(29);
        LocalDate safeTo = toDate != null ? toDate : today;

        if (safeFrom.isAfter(safeTo)) {
            throw new BadRequestException("Ngày bắt đầu không được lớn hơn ngày kết thúc.");
        }
        if (safeFrom.plusDays(366).isBefore(safeTo)) {
            throw new BadRequestException("Khoang thoi gian thong ke toi da la 366 ngay.");
        }

        LocalDateTime fromDateTime = safeFrom.atStartOfDay();
        LocalDateTime toDateTimeExclusive = safeTo.plusDays(1).atStartOfDay();

        Map<BehaviorEventType, Long> eventCounts = new EnumMap<>(BehaviorEventType.class);
        for (UserBehaviorEventRepository.EventTypeCount eventTypeCount
                : eventRepository.countByEventTypeBetween(fromDateTime, toDateTimeExclusive)) {
            if (eventTypeCount.getEventType() != null) {
                eventCounts.put(eventTypeCount.getEventType(), eventTypeCount.getEventCount());
            }
        }

        long totalEvents = eventCounts.values().stream().mapToLong(Long::longValue).sum();
        long totalProductViews = eventCounts.getOrDefault(BehaviorEventType.PRODUCT_VIEW, 0L);
        long totalSearches = eventCounts.getOrDefault(BehaviorEventType.PRODUCT_SEARCH, 0L);
        long totalCartAdds = eventCounts.getOrDefault(BehaviorEventType.ADD_TO_CART, 0L);
        long totalPurchases = eventCounts.getOrDefault(BehaviorEventType.PURCHASE, 0L);
        long totalReviews = eventCounts.getOrDefault(BehaviorEventType.PRODUCT_REVIEW, 0L);
        long averageStaySeconds = Math.round(Optional.ofNullable(
                eventRepository.averagePageStaySecondsBetween(fromDateTime, toDateTimeExclusive)).orElse(0D));

        Map<String, Long> topProductScores = toMetricMap(eventRepository.findTopProductMetricsBetween(
                fromDateTime,
                toDateTimeExclusive,
                PageRequest.of(0, DEFAULT_TOP_ITEMS_LIMIT)));
        Map<String, Product> productMap = productRepository.findAllById(topProductScores.keySet()).stream()
                .collect(Collectors.toMap(Product::getId, Function.identity(), (left, right) -> left));

        List<NamedMetricResponse> topProducts = topProductScores.entrySet().stream()
                .limit(DEFAULT_TOP_ITEMS_LIMIT)
                .map(entry -> {
                    Product product = productMap.get(entry.getKey());
                    String label = product != null ? product.getTenSanPham() : entry.getKey();
                    return new NamedMetricResponse(entry.getKey(), label, entry.getValue());
                })
                .toList();

        List<NamedMetricResponse> topCategories = toNamedMetrics(toMetricMap(eventRepository.findTopCategoryMetricsBetween(
                fromDateTime,
                toDateTimeExclusive,
                PageRequest.of(0, DEFAULT_TOP_ITEMS_LIMIT))));
        List<NamedMetricResponse> topKeywords = toNamedMetrics(buildKeywordMetricMap(
                eventRepository.findTopSearchKeywordMetricsBetween(
                        fromDateTime,
                        toDateTimeExclusive,
                        PageRequest.of(0, ADMIN_KEYWORD_CANDIDATE_LIMIT)),
                DEFAULT_TOP_ITEMS_LIMIT));
        List<NamedMetricResponse> topPriceBuckets = toNamedMetrics(toMetricMap(
                eventRepository.findTopPriceBucketMetricsBetween(
                        fromDateTime,
                        toDateTimeExclusive,
                        PageRequest.of(0, DEFAULT_TOP_ITEMS_LIMIT))));

        BigDecimal totalRevenue = orderRepository.sumPaidRevenueBetween(safeFrom, safeTo);

        return new AdminBehaviorAnalyticsResponse(
                safeFrom,
                safeTo,
                totalEvents,
                eventRepository.countDistinctAuthenticatedUsersBetween(fromDateTime, toDateTimeExclusive),
                totalProductViews,
                totalSearches,
                totalCartAdds,
                totalPurchases,
                totalReviews,
                averageStaySeconds,
                totalRevenue,
                topProducts,
                topCategories,
                topKeywords,
                topPriceBuckets);
    }

    private String requireUserId(Authentication authentication) {
        String userId = resolveUserId(authentication);
        if (userId == null) {
            throw new BadRequestException("Không tìm thấy người dùng hiện tại.");
        }
        return userId;
    }

    private String resolveUserId(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }

        String username = trimToNull(authentication.getName());
        if (username == null) {
            return null;
        }

        return userRepository.findByUsernameIgnoreCase(username)
                .map(User::getId)
                .orElse(null);
    }

    private Product resolveProduct(String productId) {
        String normalizedId = trimToNull(productId);
        if (normalizedId == null) {
            return null;
        }
        return productRepository.findActiveById(normalizedId).orElse(null);
    }

    private CanonicalPublicEvent canonicalizePublicEvent(TrackBehaviorEventRequest request, String userId) {
        BehaviorEventType eventType = request.eventType();
        if (eventType == BehaviorEventType.PURCHASE) {
            throw new BadRequestException("Su kien mua hang chi duoc ghi nhan boi may chu.");
        }
        if (eventType == BehaviorEventType.PRODUCT_REVIEW) {
            throw new BadRequestException("Su kien danh gia chi duoc ghi nhan boi may chu.");
        }
        if ((eventType == BehaviorEventType.ADD_TO_CART || eventType == BehaviorEventType.REMOVE_FROM_CART)
                && trimToNull(userId) == null) {
            throw new BadRequestException("Can dang nhap de ghi nhan su kien gio hang.");
        }

        boolean requiresProduct = eventType == BehaviorEventType.PRODUCT_VIEW
                || eventType == BehaviorEventType.ADD_TO_CART
                || eventType == BehaviorEventType.REMOVE_FROM_CART;
        String requestedProductId = trimToNull(request.productId());
        Product product = requiresProduct ? requireActiveProduct(requestedProductId) : resolveProduct(requestedProductId);
        if (!requiresProduct && requestedProductId != null && product == null) {
            throw new BadRequestException("San pham cua su kien khong ton tai hoac da ngung ban.");
        }

        String pageKey = trimToNull(request.pageKey());
        String categoryKey = null;
        String brandKey = null;
        String searchKeyword = null;
        BigDecimal priceValue = null;
        Integer quantity = null;
        Integer durationSeconds = null;

        if (product != null) {
            pageKey = firstNonBlank(product.getSku(), product.getId());
            categoryKey = cleanKey(product.getDanhMuc());
            brandKey = cleanKey(product.getThuongHieu());
            priceValue = product.getGiaBan();
        }

        switch (eventType) {
            case PRODUCT_SEARCH -> {
                searchKeyword = requireSearchKeyword(request.searchKeyword());
                pageKey = "search";
                // A search event is not a product interaction. Ignore all client supplied product
                // and catalog attributes so a request cannot manufacture a product score.
                product = null;
                categoryKey = null;
                brandKey = null;
                priceValue = null;
            }
            case CATEGORY_CLICK -> {
                if (product == null) {
                    categoryKey = resolveKnownCategory(request.categoryKey());
                    brandKey = resolveKnownBrand(request.brandKey());
                    if ((categoryKey == null && brandKey == null) || (categoryKey != null && brandKey != null)) {
                        throw new BadRequestException("Su kien danh muc phai tham chieu dung mot danh muc hoac thuong hieu hop le.");
                    }
                }
                pageKey = categoryKey != null ? "category:" + categoryKey : "brand:" + brandKey;
            }
            case PAGE_STAY -> {
                if (request.durationSeconds() == null || request.durationSeconds() <= 0) {
                    throw new BadRequestException("Thoi gian o lai trang phai lon hon 0.");
                }
                durationSeconds = Math.min(request.durationSeconds(), MAX_TRACKED_PAGE_STAY_SECONDS);
                searchKeyword = normalizeSearchKeyword(request.searchKeyword());
                if (product == null) {
                    // Page stays may refer to a category/brand page. Keep only values which can be
                    // resolved against the current catalog; unknown values are not persisted.
                    categoryKey = resolveKnownCategory(request.categoryKey());
                    brandKey = resolveKnownBrand(request.brandKey());
                    pageKey = normalizePageKey(pageKey);
                }
            }
            case ADD_TO_CART, REMOVE_FROM_CART -> quantity = 1;
            case PRODUCT_VIEW -> {
                // Product details were populated from the database above.
            }
            case PURCHASE, PRODUCT_REVIEW -> throw new BadRequestException("Su kien chi duoc ghi nhan boi may chu.");
        }

        return new CanonicalPublicEvent(
                pageKey,
                product != null ? product.getId() : null,
                categoryKey,
                brandKey,
                searchKeyword,
                priceValue,
                quantity,
                durationSeconds);
    }

    private Product requireActiveProduct(String productId) {
        Product product = resolveProduct(productId);
        if (product == null) {
            throw new BadRequestException("Su kien san pham phai tham chieu san pham dang kinh doanh.");
        }
        return product;
    }

    private String resolveKnownCategory(String category) {
        String normalized = cleanKey(category);
        if (normalized == null) {
            return null;
        }
        return productRepository.findActiveByCategoryIgnoreCase(normalized, PageRequest.of(0, 1)).stream()
                .findFirst()
                .map(Product::getDanhMuc)
                .map(this::cleanKey)
                .orElse(null);
    }

    private String resolveKnownBrand(String brand) {
        String normalized = cleanKey(brand);
        if (normalized == null) {
            return null;
        }
        return productRepository.findActiveByBrandIgnoreCase(normalized, PageRequest.of(0, 1)).stream()
                .findFirst()
                .map(Product::getThuongHieu)
                .map(this::cleanKey)
                .orElse(null);
    }

    private String requireSearchKeyword(String keyword) {
        String normalized = normalizeSearchKeyword(keyword);
        if (normalized == null) {
            throw new BadRequestException("Tu khoa tim kiem la bat buoc cho su kien tim kiem.");
        }
        return normalized;
    }

    private String normalizeSearchKeyword(String keyword) {
        String normalized = cleanKey(keyword);
        return normalized == null ? null : normalized.substring(0, Math.min(normalized.length(), 120));
    }

    private String normalizePageKey(String pageKey) {
        String normalized = cleanKey(pageKey);
        return normalized == null ? null : normalized.substring(0, Math.min(normalized.length(), 120));
    }

    private String normalizeTrustedSessionId(String sessionId) {
        String normalized = trimToNull(sessionId);
        if (normalized == null || !normalized.matches("analytics-[0-9a-fA-F-]{36}")) {
            return "analytics-" + UUID.randomUUID();
        }
        return normalized;
    }

    // Hàm cộng dồn tính toán các điểm hành vi
    private BehaviorSnapshot buildSnapshot(List<UserBehaviorEvent> inputEvents) {
        List<UserBehaviorEvent> events = inputEvents == null ? List.of()
                : inputEvents.stream()
                        .filter(Objects::nonNull)
                        .limit(PROFILE_EVENT_LOOKBACK)
                        .toList();

        Map<String, Long> categoryScores = new LinkedHashMap<>();
        Map<String, Long> brandScores = new LinkedHashMap<>();
        Map<String, Long> keywordScores = new LinkedHashMap<>();
        Map<String, Long> priceBucketScores = new LinkedHashMap<>();
        String lastViewedProductId = null;
        int totalPurchases = 0;
        int totalStaySeconds = 0;
        int totalStayEvents = 0;
        BigDecimal priceMin = null;
        BigDecimal priceMax = null;

        for (UserBehaviorEvent event : events) {
            long weight = resolveEventWeight(event);

            mergeScore(categoryScores, event.getCategoryKey(), weight);
            mergeScore(brandScores, event.getBrandKey(), weight);
            mergeScore(priceBucketScores, event.getPriceBucket(), weight);

            if (event.getSearchKeyword() != null) {
                tokenizeSearchKeyword(event.getSearchKeyword())
                        .forEach(token -> mergeScore(keywordScores, token, weight));
            }

            if (lastViewedProductId == null
                    && event.getEventType() == BehaviorEventType.PRODUCT_VIEW
                    && trimToNull(event.getProductId()) != null) {
                lastViewedProductId = event.getProductId();
            }

            if (event.getEventType() == BehaviorEventType.PURCHASE) {
                totalPurchases += 1;
            }

            if (event.getDurationSeconds() != null && event.getDurationSeconds() > 0) {
                totalStaySeconds += event.getDurationSeconds();
                totalStayEvents += 1;
            }

            if (event.getPriceValue() != null) {
                priceMin = priceMin == null ? event.getPriceValue() : priceMin.min(event.getPriceValue());
                priceMax = priceMax == null ? event.getPriceValue() : priceMax.max(event.getPriceValue());
            }
        }

        return new BehaviorSnapshot(
                toOrderedMap(categoryScores, DEFAULT_PROFILE_TOP_LIMIT),
                toOrderedMap(brandScores, DEFAULT_PROFILE_TOP_LIMIT),
                toOrderedMap(keywordScores, DEFAULT_PROFILE_TOP_LIMIT),
                toOrderedMap(priceBucketScores, DEFAULT_PROFILE_TOP_LIMIT),
                getTopKey(categoryScores),
                getTopKey(brandScores),
                getTopKey(priceBucketScores),
                lastViewedProductId,
                events.size(),
                totalPurchases,
                totalStayEvents == 0 ? 0 : Math.round((float) totalStaySeconds / totalStayEvents),
                priceMin,
                priceMax);
    }

    // Hàm quy định giá trị điểm của mỗi hành vi
    private long resolveEventWeight(UserBehaviorEvent event) {
        if (event == null || event.getEventType() == null) {
            return 1;
        }

        return switch (event.getEventType()) {
            case PRODUCT_VIEW -> 3;
            case PRODUCT_SEARCH -> 4;
            case CATEGORY_CLICK -> 3;
            case ADD_TO_CART -> 8;
            case REMOVE_FROM_CART -> 2;
            case PURCHASE -> 12;
            case PRODUCT_REVIEW -> 9;
            case PAGE_STAY ->
                Math.max(1, Math.round((event.getDurationSeconds() == null ? 0 : event.getDurationSeconds()) / 20.0f));
        };
    }

    // Hàm tính độ phổ biến các sản phẩm
    private Map<String, Long> buildWeightedProductMap(List<UserBehaviorEvent> events, int limit) {
        Map<String, Long> scoreMap = new LinkedHashMap<>();
        if (events == null) {
            return scoreMap;
        }

        for (UserBehaviorEvent event : events) {
            String productId = trimToNull(event.getProductId());
            if (productId == null) {
                continue;
            }

            // Dựa theo số lượt xem, thêm vào giỏ, mua hàng, đánh giá
            long weight = switch (event.getEventType()) {
                case PRODUCT_VIEW -> 1;
                case ADD_TO_CART -> 4;
                case PURCHASE -> 8;
                case PRODUCT_REVIEW -> 5;
                case PRODUCT_SEARCH, CATEGORY_CLICK, REMOVE_FROM_CART, PAGE_STAY -> 1;
            };
            scoreMap.merge(productId, weight, Long::sum);
        }

        return toOrderedMap(scoreMap, limit);
    }

    private Map<String, Long> toMetricMap(List<UserBehaviorEventRepository.MetricValue> metrics) {
        Map<String, Long> scoreMap = new LinkedHashMap<>();
        if (metrics == null) {
            return scoreMap;
        }

        for (UserBehaviorEventRepository.MetricValue metric : metrics) {
            String key = cleanKey(metric.getMetricKey());
            Long score = metric.getScore();
            if (key != null && score != null && score > 0) {
                scoreMap.putIfAbsent(key, score);
            }
        }
        return scoreMap;
    }

    private Map<String, Long> buildKeywordMetricMap(
            List<UserBehaviorEventRepository.MetricValue> keywordMetrics,
            int limit) {
        Map<String, Long> scoreMap = new LinkedHashMap<>();
        if (keywordMetrics == null) {
            return scoreMap;
        }

        for (UserBehaviorEventRepository.MetricValue metric : keywordMetrics) {
            long score = metric.getScore() == null ? 0L : metric.getScore();
            if (score <= 0) {
                continue;
            }
            tokenizeSearchKeyword(metric.getMetricKey())
                    .forEach(token -> scoreMap.merge(token, score, Long::sum));
        }
        return toOrderedMap(scoreMap, limit);
    }

    private Map<String, Long> buildWeightedStringMap(
            Collection<UserBehaviorEvent> events,
            Function<UserBehaviorEvent, String> extractor,
            int limit) {
        Map<String, Long> scoreMap = new LinkedHashMap<>();
        if (events == null) {
            return scoreMap;
        }

        for (UserBehaviorEvent event : events) {
            mergeScore(scoreMap, extractor.apply(event), resolveEventWeight(event));
        }

        return toOrderedMap(scoreMap, limit);
    }

    private Map<String, Long> buildKeywordMap(Collection<UserBehaviorEvent> events, int limit) {
        Map<String, Long> scoreMap = new LinkedHashMap<>();
        if (events == null) {
            return scoreMap;
        }

        for (UserBehaviorEvent event : events) {
            if (event.getSearchKeyword() == null) {
                continue;
            }

            tokenizeSearchKeyword(event.getSearchKeyword())
                    .forEach(token -> mergeScore(scoreMap, token, resolveEventWeight(event)));
        }

        return toOrderedMap(scoreMap, limit);
    }

    // Hàm thực hiện cộng điểm hành vi
    private void mergeScore(Map<String, Long> scoreMap, String rawKey, long weight) {
        String key = cleanKey(rawKey);
        if (key == null || weight <= 0) {
            return;
        }
        scoreMap.merge(key, weight, Long::sum);
    }

    private List<String> tokenizeSearchKeyword(String rawKeyword) {
        String normalized = trimToNull(rawKeyword);
        if (normalized == null) {
            return List.of();
        }

        return List.of(normalized.toLowerCase(Locale.ROOT).split("\\s+")).stream()
                .map(this::trimToNull)
                .filter(Objects::nonNull)
                .filter(token -> token.length() >= 2)
                .distinct()
                .toList();
    }

    private String resolvePriceBucket(BigDecimal priceValue) {
        if (priceValue == null) {
            return null;
        }
        if (priceValue.compareTo(BigDecimal.valueOf(500_000)) < 0) {
            return "DUOI_500K";
        }
        if (priceValue.compareTo(BigDecimal.valueOf(1_000_000)) < 0) {
            return "500K_1M";
        }
        if (priceValue.compareTo(BigDecimal.valueOf(2_000_000)) < 0) {
            return "1M_2M";
        }
        if (priceValue.compareTo(BigDecimal.valueOf(5_000_000)) < 0) {
            return "2M_5M";
        }
        return "TREN_5M";
    }

    private String cleanKey(String value) {
        String normalized = trimToNull(value);
        return normalized == null ? null : normalized.replaceAll("\\s+", " ");
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String firstNonBlank(String primary, String fallback) {
        String normalizedPrimary = trimToNull(primary);
        return normalizedPrimary != null ? normalizedPrimary : trimToNull(fallback);
    }

    private String writeJson(Object value) {
        if (value == null) {
            return null;
        }

        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException exception) {
            return null;
        }
    }

    private Map<String, Long> toOrderedMap(Map<String, Long> input, int limit) {
        int safeLimit = Math.max(limit, 1);
        Comparator<Map.Entry<String, Long>> worstFirst = Map.Entry.<String, Long>comparingByValue()
                .thenComparing(Map.Entry::getKey, String.CASE_INSENSITIVE_ORDER.reversed());
        PriorityQueue<Map.Entry<String, Long>> topEntries = new PriorityQueue<>(safeLimit, worstFirst);

        input.entrySet().stream()
                .filter(entry -> entry.getKey() != null && !entry.getKey().isBlank())
                .forEach(entry -> {
                    if (topEntries.size() < safeLimit) {
                        topEntries.offer(entry);
                    } else if (worstFirst.compare(entry, topEntries.peek()) > 0) {
                        topEntries.poll();
                        topEntries.offer(entry);
                    }
                });

        return topEntries.stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry::getKey, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (left, right) -> left,
                        LinkedHashMap::new));
    }

    private String getTopKey(Map<String, Long> input) {
        return toOrderedMap(input, 1).keySet().stream().findFirst().orElse(null);
    }

    private UserBehaviorInsightResponse toInsightResponse(UserBehaviorProfile profile) {
        return new UserBehaviorInsightResponse(
                profile.getFavoriteCategory(),
                profile.getFavoriteBrand(),
                profile.getPreferredPriceBucket(),
                profile.getPriceMin(),
                profile.getPriceMax(),
                readMetricJson(profile.getTopCategoriesJson()),
                readMetricJson(profile.getTopBrandsJson()),
                readMetricJson(profile.getTopKeywordsJson()),
                profile.getLastViewedProductId(),
                Optional.ofNullable(profile.getTotalInteractions()).orElse(0),
                Optional.ofNullable(profile.getTotalPurchases()).orElse(0),
                Optional.ofNullable(profile.getAverageStaySeconds()).orElse(0),
                profile.getUpdatedAt());
    }

    private List<NamedMetricResponse> readMetricJson(String json) {
        String source = trimToNull(json);
        if (source == null) {
            return List.of();
        }

        try {
            Map<String, Long> data = objectMapper.readValue(source, new TypeReference<LinkedHashMap<String, Long>>() {
            });
            return toNamedMetrics(data);
        } catch (JsonProcessingException exception) {
            return List.of();
        }
    }

    private List<NamedMetricResponse> toNamedMetrics(Map<String, Long> scoreMap) {
        return scoreMap.entrySet().stream()
                .map(entry -> new NamedMetricResponse(entry.getKey(), translateBucketLabel(entry.getKey()),
                        entry.getValue()))
                .toList();
    }

    private String translateBucketLabel(String key) {
        return switch (String.valueOf(key)) {
            case "DUOI_500K" -> "Dưới 500.000đ";
            case "500K_1M" -> "500.000đ - 1.000.000đ";
            case "1M_2M" -> "1.000.000đ - 2.000.000đ";
            case "2M_5M" -> "2.000.000đ - 5.000.000đ";
            case "TREN_5M" -> "Trên 5.000.000đ";
            default -> key;
        };
    }

    private boolean sameIgnoreCase(String left, String right) {
        return cleanKey(left) != null
                && cleanKey(right) != null
                && cleanKey(left).equalsIgnoreCase(cleanKey(right));
    }

    private String buildRecommendationCacheKey(
            String userId,
            String sessionId,
            String context,
            String productId,
            List<String> productIds,
            int limit) {
        String principal = trimToNull(userId) != null
                ? "user:" + trimToNull(userId)
                : "session:" + Optional.ofNullable(trimToNull(sessionId)).orElse("anonymous");
        String relatedProducts = productIds == null
                ? ""
                : productIds.stream()
                        .map(this::trimToNull)
                        .filter(Objects::nonNull)
                        .sorted()
                        .collect(Collectors.joining(","));

        return String.join("|",
                principal,
                Optional.ofNullable(trimToNull(context)).orElse("home"),
                "limit:" + limit,
                "product:" + Optional.ofNullable(trimToNull(productId)).orElse(""),
                "items:" + relatedProducts);
    }

    private Map<String, Long> getPopularityScores(LocalDateTime now) {
        try {
            String cached = redisTemplate.opsForValue().get(popularityCacheKey);
            if (cached != null) {
                return objectMapper.readValue(cached, new TypeReference<LinkedHashMap<String, Long>>() {
                });
            }
        } catch (RuntimeException | JsonProcessingException ignored) {
            safeDeleteRedisKey(popularityCacheKey);
        }
        // Only authenticated activity contributes to globally shared scores.
        // Anonymous events remain available to their browser-session snapshot,
        // but cannot let a bot skew the catalog-wide recommendations.
        Map<String, Long> scores = buildWeightedProductMap(
                eventRepository.findTrustedByCreatedAtAfterOrderByCreatedAtDesc(
                        now.minusDays(30),
                        PageRequest.of(0, POPULARITY_LOOKBACK_EVENTS)),
                60);
        try {
            redisTemplate.opsForValue().set(
                    popularityCacheKey,
                    objectMapper.writeValueAsString(scores),
                    popularityCacheTtl);
        } catch (RuntimeException | JsonProcessingException ignored) {
            safeDeleteRedisKey(popularityCacheKey);
        }
        return scores;
    }

    private List<ProductResponse> readRecommendationCache(String cacheKey) {
        String redisKey = recommendationCachePrefix + cacheKey;
        try {
            String cached = redisTemplate.opsForValue().get(redisKey);
            if (cached == null) {
                return null;
            }
            return objectMapper.readValue(cached, new TypeReference<List<ProductResponse>>() {
            });
        } catch (RuntimeException | JsonProcessingException ignored) {
            safeDeleteRedisKey(redisKey);
            return null;
        }
    }

    private void cacheRecommendations(String cacheKey, List<ProductResponse> recommendations) {
        String redisKey = recommendationCachePrefix + cacheKey;
        try {
            redisTemplate.opsForValue().set(
                    redisKey,
                    objectMapper.writeValueAsString(recommendations),
                    recommendationCacheTtl);
        } catch (RuntimeException | JsonProcessingException ignored) {
            safeDeleteRedisKey(redisKey);
        }
    }

    private void safeDeleteRedisKey(String key) {
        try {
            redisTemplate.delete(key);
        } catch (RuntimeException ignored) {
            // Recommendation fallback must continue when Redis is temporarily unavailable.
        }
    }

    private ProductResponse toProductResponse(Product product) {
        return new ProductResponse(
                product.getId(),
                product.getTenSanPham(),
                product.getSku(),
                product.getDanhMuc(),
                product.getThuongHieu(),
                product.getSize(),
                product.getMau(),
                null,
                product.getGiaBan(),
                product.getTonKho() == null ? 0 : Math.min(product.getTonKho(), 10),
                product.getTrangThai(),
                product.getLinkSanPham(),
                product.getHinhAnhUrl(),
                null,
                product.getCreatedAt(),
                List.of());
    }

    private record ProductScore(Product product, long score) {
    }

    private record CanonicalPublicEvent(
            String pageKey,
            String productId,
            String categoryKey,
            String brandKey,
            String searchKeyword,
            BigDecimal priceValue,
            Integer quantity,
            Integer durationSeconds) {
    }

    private record BehaviorSnapshot(
            Map<String, Long> categoryScores,
            Map<String, Long> brandScores,
            Map<String, Long> topKeywords,
            Map<String, Long> priceBucketScores,
            String favoriteCategory,
            String favoriteBrand,
            String preferredPriceBucket,
            String lastViewedProductId,
            int totalInteractions,
            int totalPurchases,
            int averageStaySeconds,
            BigDecimal priceMin,
            BigDecimal priceMax) {
        private Map<String, Long> topCategories() {
            return categoryScores;
        }

        private Map<String, Long> topBrands() {
            return brandScores;
        }
    }
}
