package com.flarefitness.backend.dto.order;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;

public record OrderItemPayload(
        @JsonAlias("productId") @NotBlank String productId,
        @JsonAlias("variantId") @Size(max = 64) String variantId,
        @Size(max = 64) String sku,
        @Size(max = 255) String name,
        @Size(max = 500) String image,
        @Size(max = 50) String size,
        @JsonAlias("variantType") @Size(max = 50) String variantType,
        @Min(1) @Max(10) Integer quantity,
        @JsonAlias("unitPrice") BigDecimal unitPrice,
        BigDecimal subtotal
) {
}
