package com.flarefitness.backend.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.dto.product.ProductVariantResponse;
import com.flarefitness.backend.dto.product.UpsertProductRequest;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductVariant;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductVariantRepository;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.List;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class ProductService {

    private static final int LEGACY_LIST_LIMIT = 100;

    private final ProductRepository productRepository;
    private final ProductVariantRepository productVariantRepository;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final String productPrefix;
    private final String productListKey;
    private final String publicProductListKey;
    private final long ttlSeconds;

    public ProductService(
            ProductRepository productRepository,
            ProductVariantRepository productVariantRepository,
            StringRedisTemplate redisTemplate,
            ObjectMapper objectMapper,
            @Value("${app.cache.product-prefix}") String productPrefix,
            @Value("${app.cache.product-list-key}") String productListKey,
            @Value("${app.cache.product-ttl-seconds}") long ttlSeconds) {
        this.productRepository = productRepository;
        this.productVariantRepository = productVariantRepository;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.productPrefix = productPrefix;
        this.productListKey = productListKey;
        this.publicProductListKey = productListKey + ":public";
        this.ttlSeconds = ttlSeconds;
    }

    /**
     * Compatibility endpoint support.  Do not turn this back into an unbounded catalog read:
     * callers that need more results must use the page endpoint.
     */
    @Transactional(readOnly = true)
    public List<ProductResponse> getAllProducts() {
        return getAllProductsPage(0, LEGACY_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public List<ProductResponse> getAllPublicProducts() {
        return getAllPublicProductsPage(0, LEGACY_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public PageResponse<ProductResponse> getAllProductsPage(Integer page, Integer size) {
        Page<Product> products = productRepository.findAllByOrderByCreatedAtDesc(pageRequest(page, size));
        return pageResponse(products, false);
    }

    @Transactional(readOnly = true)
    public PageResponse<ProductResponse> getAllPublicProductsPage(Integer page, Integer size) {
        Page<Product> products = productRepository.findAllByOrderByCreatedAtDesc(pageRequest(page, size));
        return pageResponse(products, true);
    }

    public ProductResponse getProductById(String id) {
        String cacheKey = productPrefix + id;
        String cachedJson = redisTemplate.opsForValue().get(cacheKey);
        if (cachedJson != null) {
            try {
                return objectMapper.readValue(cachedJson, ProductResponse.class);
            } catch (JsonProcessingException ignored) {
                redisTemplate.delete(cacheKey);
            }
        }

        Product product = productRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy sản phẩm."));
        ProductResponse response = toResponse(product, variantsByProductId(List.of(product.getId())).get(product.getId()), false);
        cache(cacheKey, response);
        return response;
    }

    public ProductResponse getPublicProductById(String id) {
        Product product = productRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy sản phẩm."));
        return toResponse(product, variantsByProductId(List.of(product.getId())).get(product.getId()), true);
    }

    public PageResponse<ProductResponse> queryProducts(
            String query,
            String category,
            String brand,
            String status,
            BigDecimal minPrice,
            BigDecimal maxPrice,
            Boolean inStock,
            Integer page,
            Integer size) {
        PageRequest pageable = pageRequest(page, size);
        String normalizedQuery = trimToNull(query);
        String booleanSearchQuery = toBooleanSearchQuery(normalizedQuery);
        int inStockOnly = Boolean.TRUE.equals(inStock) ? 1 : 0;

        Page<Product> products;
        if (normalizedQuery != null && booleanSearchQuery == null) {
            products = searchProductsFallback(
                    normalizedQuery,
                    category,
                    brand,
                    status,
                    minPrice,
                    maxPrice,
                    inStockOnly,
                    pageable);
        } else {
            try {
                products = productRepository.searchProducts(
                        booleanSearchQuery,
                        trimToNull(category),
                        trimToNull(brand),
                        trimToNull(status),
                        minPrice,
                        maxPrice,
                        inStockOnly,
                        pageable);
            } catch (DataAccessException exception) {
                products = searchProductsFallback(
                        normalizedQuery, category, brand, status, minPrice, maxPrice, inStockOnly, pageable);
            }
        }

        return new PageResponse<>(
                toResponses(products.getContent(), true),
                products.getNumber(),
                products.getSize(),
                products.getTotalElements(),
                products.getTotalPages(),
                products.hasNext());
    }

    @Transactional
    public ProductResponse createProduct(UpsertProductRequest request) {
        productRepository.findBySkuIgnoreCase(request.sku())
                .ifPresent(existing -> {
                    throw new BadRequestException("SKU đã tồn tại.");
                });

        Product product = new Product();
        product.setId(UUID.randomUUID().toString());
        product.setCreatedAt(LocalDateTime.now());
        product.setDeleted(false);
        apply(product, request);

        Product saved = productRepository.save(product);
        evictProductCaches(saved.getId());
        return toResponse(saved, List.of(), false);
    }

    @Transactional
    public ProductResponse updateProduct(String id, UpsertProductRequest request) {
        Product product = productRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy sản phẩm."));

        productRepository.findBySkuIgnoreCase(request.sku())
                .filter(existing -> !existing.getId().equals(id))
                .ifPresent(existing -> {
                    throw new BadRequestException("SKU đã tồn tại.");
                });

        apply(product, request);
        Product saved = productRepository.save(product);
        evictProductCaches(id);
        return toResponse(saved, variantsByProductId(List.of(saved.getId())).get(saved.getId()), false);
    }

    @Transactional
    public void deleteProduct(String id) {
        Product product = productRepository.findActiveById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy sản phẩm."));
        product.setDeleted(true);
        product.setTrangThai("Ngung kinh doanh");
        productRepository.save(product);
        evictProductCaches(id);
    }

    private void apply(Product product, UpsertProductRequest request) {
        validateImageSources(request.hinhAnhUrl());
        product.setTenSanPham(request.tenSanPham());
        product.setSku(request.sku());
        product.setDanhMuc(request.danhMuc());
        product.setThuongHieu(request.thuongHieu());
        product.setSize(request.size());
        product.setMau(request.mau());
        product.setGiaNhap(request.giaNhap());
        product.setGiaBan(request.giaBan());
        product.setTonKho(request.tonKho());
        product.setTrangThai(request.trangThai());
        product.setLinkSanPham(request.linkSanPham());
        product.setHinhAnhUrl(request.hinhAnhUrl());
        product.setGhiChu(request.ghiChu());
    }

    private void validateImageSources(String value) {
        if (value == null || value.isBlank()) {
            return;
        }

        String[] imageSources = value.split("\\r?\\n|\\|");
        for (String source : imageSources) {
            String trimmed = source.trim();
            if (!trimmed.isBlank() && !isAllowedImageSource(trimmed)) {
                throw new BadRequestException("Duong dan anh san pham khong hop le.");
            }
        }
    }

    private boolean isAllowedImageSource(String value) {
        if (value.length() > 500
                || value.startsWith("//")
                || value.contains("\\")
                || value.matches(".*[\\p{Cntrl}<>'\"].*")) {
            return false;
        }

        String lowerValue = value.toLowerCase(java.util.Locale.ROOT);
        if (lowerValue.startsWith("javascript:") || lowerValue.startsWith("data:")) {
            return false;
        }

        try {
            URI uri = new URI(value);
            if (uri.isAbsolute()) {
                String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(java.util.Locale.ROOT);
                return "https".equals(scheme);
            }
        } catch (URISyntaxException exception) {
            return false;
        }

        return value.startsWith("./")
                || value.startsWith("/")
                || value.startsWith("assets/");
    }

    private List<ProductResponse> toResponses(List<Product> products, boolean publicResponse) {
        if (products.isEmpty()) {
            return List.of();
        }
        Map<String, List<ProductVariant>> variantsByProductId = variantsByProductId(
                products.stream().map(Product::getId).toList());
        return products.stream()
                .map(product -> toResponse(product, variantsByProductId.get(product.getId()), publicResponse))
                .toList();
    }

    private PageResponse<ProductResponse> pageResponse(Page<Product> products, boolean publicResponse) {
        return new PageResponse<>(
                toResponses(products.getContent(), publicResponse),
                products.getNumber(),
                products.getSize(),
                products.getTotalElements(),
                products.getTotalPages(),
                products.hasNext());
    }

    private PageRequest pageRequest(Integer page, Integer size) {
        int safePage = Math.max(page == null ? 0 : page, 0);
        int safeSize = Math.min(Math.max(size == null ? 24 : size, 1), LEGACY_LIST_LIMIT);
        return PageRequest.of(safePage, safeSize);
    }

    private Map<String, List<ProductVariant>> variantsByProductId(Collection<String> productIds) {
        if (productIds == null || productIds.isEmpty()) {
            return Map.of();
        }
        return productVariantRepository.findActiveByProductIdIn(productIds).stream()
                .collect(Collectors.groupingBy(ProductVariant::getProductId));
    }

    private ProductResponse toResponse(Product product, List<ProductVariant> variants, boolean publicResponse) {
        List<ProductVariantResponse> variantResponses = (variants == null ? List.<ProductVariant>of() : variants).stream()
                .map(variant -> toVariantResponse(variant, publicResponse))
                .toList();
        return new ProductResponse(
                product.getId(),
                product.getTenSanPham(),
                product.getSku(),
                product.getDanhMuc(),
                product.getThuongHieu(),
                product.getSize(),
                product.getMau(),
                publicResponse ? null : product.getGiaNhap(),
                product.getGiaBan(),
                publicResponse ? (product.getTonKho() == null ? 0 : Math.min(product.getTonKho(), 10)) : product.getTonKho(),
                product.getTrangThai(),
                product.getLinkSanPham(),
                product.getHinhAnhUrl(),
                publicResponse ? null : product.getGhiChu(),
                product.getCreatedAt(),
                variantResponses);
    }

    private ProductVariantResponse toVariantResponse(ProductVariant variant, boolean publicResponse) {
        int stock = variant.getTonKho() == null ? 0 : variant.getTonKho();
        return new ProductVariantResponse(
                variant.getId(),
                variant.getSku(),
                variant.getSize(),
                variant.getMau(),
                variant.getGiaBan(),
                publicResponse ? Math.min(stock, 10) : stock,
                variant.getHinhAnhUrl());
    }

    private String toBooleanSearchQuery(String value) {
        String normalized = trimToNull(value);
        if (normalized == null) {
            return null;
        }
        String query = Arrays.stream(normalized.toLowerCase(Locale.ROOT).split("\\s+"))
                .map(String::trim)
                .filter(token -> token.length() >= 2)
                .map(token -> "+" + token.replaceAll("[^\\p{L}\\p{N}-]", "") + "*")
                .filter(token -> token.length() > 2)
                .reduce((left, right) -> left + " " + right)
                .orElse("");
        return query.isBlank() ? null : query;
    }

    private Page<Product> searchProductsFallback(
            String query,
            String category,
            String brand,
            String status,
            BigDecimal minPrice,
            BigDecimal maxPrice,
            int inStockOnly,
            PageRequest pageable) {
        return productRepository.searchProductsFallback(
                query == null ? null : "%" + query + "%",
                trimToNull(category),
                trimToNull(brand),
                trimToNull(status),
                minPrice,
                maxPrice,
                inStockOnly,
                pageable);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private void cache(String key, Object value) {
        try {
            redisTemplate.opsForValue().set(key, objectMapper.writeValueAsString(value),
                    Duration.ofSeconds(ttlSeconds));
        } catch (JsonProcessingException ignored) {
            redisTemplate.delete(key);
        }
    }

    private void evictProductCaches(String id) {
        redisTemplate.delete(productListKey);
        redisTemplate.delete(publicProductListKey);
        redisTemplate.delete(productPrefix + id);
    }

    public void evictProductCachesAfterCommit(Collection<String> ids) {
        Runnable eviction = () -> {
            try {
                redisTemplate.delete(productListKey);
                redisTemplate.delete(publicProductListKey);
                redisTemplate.delete(ids.stream().map(id -> productPrefix + id).toList());
            } catch (DataAccessException ignored) {
                // The database transaction already committed; a cache outage must not make the
                // order look failed.
            }
        };
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            eviction.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                eviction.run();
            }
        });
    }
}
