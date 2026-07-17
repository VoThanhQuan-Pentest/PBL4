package com.flarefitness.backend.entity.voucher;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbl_danh_muc_ma_giam_gia")
public class VoucherCategory {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "voucher_code", nullable = false, length = 64)
    private String voucherCode;

    @Column(name = "category_key", nullable = false, length = 160)
    private String categoryKey;

    @Column(name = "category_label", nullable = false, length = 100)
    private String categoryLabel;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getVoucherCode() {
        return voucherCode;
    }

    public void setVoucherCode(String voucherCode) {
        this.voucherCode = voucherCode;
    }

    public String getCategoryKey() {
        return categoryKey;
    }

    public void setCategoryKey(String categoryKey) {
        this.categoryKey = categoryKey;
    }

    public String getCategoryLabel() {
        return categoryLabel;
    }

    public void setCategoryLabel(String categoryLabel) {
        this.categoryLabel = categoryLabel;
    }
}
