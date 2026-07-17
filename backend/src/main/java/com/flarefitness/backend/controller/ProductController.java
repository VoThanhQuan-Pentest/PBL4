package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.service.ProductService;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public ResponseEntity<List<ProductResponse>> getProducts() {
        return ResponseEntity.ok(productService.queryProducts(
                null, null, null, null, null, null, false, 0, 100).content());
    }

    @GetMapping("/query")
    public ResponseEntity<PageResponse<ProductResponse>> queryProducts(
            @RequestParam(required = false) String q,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String brand,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) BigDecimal minPrice,
            @RequestParam(required = false) BigDecimal maxPrice,
            @RequestParam(required = false) Boolean inStock,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "24") Integer size
    ) {
        return ResponseEntity.ok(productService.queryProducts(
                q, category, brand, status, minPrice, maxPrice, inStock, page, size
        ));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProductResponse> getProduct(@PathVariable String id) {
        return ResponseEntity.ok(productService.getPublicProductById(id));
    }
}
