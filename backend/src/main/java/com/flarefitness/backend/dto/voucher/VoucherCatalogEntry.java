package com.flarefitness.backend.dto.voucher;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

/**
 * Compatibility representation used by the existing managed-vouchers sync endpoint.
 */
public record VoucherCatalogEntry(
        String code,
        String label,
        BigDecimal percent,
        BigDecimal minOrder,
        BigDecimal maxDiscount,
        List<String> categories,
        LocalDate expiresAt,
        String status
) {
}
