package com.flarefitness.backend.dto.product;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

public record ProductResponse(
        String id,
        String tenSanPham,
        String sku,
        String danhMuc,
        String thuongHieu,
        String size,
        String mau,
        BigDecimal giaNhap,
        BigDecimal giaBan,
        Integer tonKho,
        String trangThai,
        String linkSanPham,
        String hinhAnhUrl,
        String ghiChu,
        LocalDateTime ngayTao,
        List<ProductVariantResponse> variants
) {
}
