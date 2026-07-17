package com.flarefitness.backend.dto.product;

import java.math.BigDecimal;

/** Public, server-authoritative product variant information for cart and checkout. */
public record ProductVariantResponse(
        String id,
        String sku,
        String size,
        String mau,
        BigDecimal giaBan,
        Integer tonKho,
        String hinhAnhUrl
) {
}
