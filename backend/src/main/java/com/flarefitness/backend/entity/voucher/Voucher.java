package com.flarefitness.backend.entity.voucher;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "tbl_ma_giam_gia")
public class Voucher extends BaseEntity {

    @Id
    @Column(name = "ma", nullable = false, length = 64)
    private String code;

    @Column(name = "nhan", nullable = false, length = 255)
    private String label;

    @Column(name = "ty_le_giam", nullable = false, precision = 7, scale = 4)
    private BigDecimal discountPercent;

    @Column(name = "gia_tri_don_toi_thieu", nullable = false, precision = 15, scale = 2)
    private BigDecimal minimumOrder;

    @Column(name = "giam_toi_da", nullable = false, precision = 15, scale = 2)
    private BigDecimal maximumDiscount;

    @Column(name = "ngay_het_han")
    private LocalDate expiresAt;

    @Column(name = "trang_thai", nullable = false, length = 20)
    private String status;

    @Column(name = "ngay_cap_nhat", nullable = false)
    private LocalDateTime updatedAt;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public BigDecimal getDiscountPercent() {
        return discountPercent;
    }

    public void setDiscountPercent(BigDecimal discountPercent) {
        this.discountPercent = discountPercent;
    }

    public BigDecimal getMinimumOrder() {
        return minimumOrder;
    }

    public void setMinimumOrder(BigDecimal minimumOrder) {
        this.minimumOrder = minimumOrder;
    }

    public BigDecimal getMaximumDiscount() {
        return maximumDiscount;
    }

    public void setMaximumDiscount(BigDecimal maximumDiscount) {
        this.maximumDiscount = maximumDiscount;
    }

    public LocalDate getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDate expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
