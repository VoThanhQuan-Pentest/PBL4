package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductVariantRepository;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.mockito.ArgumentCaptor;

@ExtendWith(MockitoExtension.class)
class ProductServiceTest {

    @Mock private ProductRepository productRepository;
    @Mock private ProductVariantRepository productVariantRepository;
    @Mock private StringRedisTemplate redisTemplate;

    private ProductService productService;

    @BeforeEach
    void setUp() {
        productService = new ProductService(
                productRepository,
                productVariantRepository,
                redisTemplate,
                new ObjectMapper(),
                "cache:product:",
                "cache:products:all",
                300);
    }

    @Test
    void publicProductDoesNotExposeCostOrExactLargeStock() {
        Product product = product();
        when(productRepository.findActiveById(product.getId())).thenReturn(Optional.of(product));
        when(productVariantRepository.findActiveByProductIdIn(org.mockito.ArgumentMatchers.anyCollection())).thenReturn(java.util.List.of());

        ProductResponse response = productService.getPublicProductById(product.getId());

        assertThat(response.giaNhap()).isNull();
        assertThat(response.tonKho()).isEqualTo(10);
        assertThat(response.ghiChu()).isNull();
    }

    @Test
    void deleteProductUsesSoftDelete() {
        Product product = product();
        when(productRepository.findActiveById(product.getId())).thenReturn(Optional.of(product));

        productService.deleteProduct(product.getId());

        assertThat(product.getDeleted()).isTrue();
        assertThat(product.getTrangThai()).isEqualTo("Ngung kinh doanh");
        verify(productRepository).save(product);
    }

    @Test
    void adminProductPageClampsRequestedSizeToOneHundred() {
        Product product = product();
        when(productRepository.findAllByOrderByCreatedAtDesc(org.mockito.ArgumentMatchers.any(Pageable.class)))
                .thenAnswer(invocation -> {
                    Pageable pageable = invocation.getArgument(0);
                    return new PageImpl<>(List.of(product), pageable, 101);
                });
        when(productVariantRepository.findActiveByProductIdIn(org.mockito.ArgumentMatchers.anyCollection()))
                .thenReturn(List.of());

        var response = productService.getAllProductsPage(-4, 500);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(productRepository).findAllByOrderByCreatedAtDesc(pageable.capture());
        assertThat(pageable.getValue().getPageNumber()).isZero();
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
        assertThat(response.content()).extracting(ProductResponse::id).containsExactly(product.getId());
        assertThat(response.hasNext()).isTrue();
    }

    private Product product() {
        Product product = new Product();
        product.setId("product-1");
        product.setTenSanPham("Test Product");
        product.setSku("TEST-001");
        product.setDanhMuc("Test");
        product.setGiaNhap(new BigDecimal("100000"));
        product.setGiaBan(new BigDecimal("150000"));
        product.setTonKho(42);
        product.setTrangThai("Dang ban");
        product.setGhiChu("internal-note");
        product.setCreatedAt(LocalDateTime.now());
        product.setDeleted(false);
        return product;
    }
}
