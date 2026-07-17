package com.flarefitness.backend.entity.voucher;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "tbl_su_dung_ma_giam_gia")
public class VoucherRedemption extends BaseEntity {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "assignment_id", nullable = false, length = 64)
    private String assignmentId;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "voucher_code", nullable = false, length = 64)
    private String voucherCode;

    /**
     * Nullable in the database only so historic redemptions imported before
     * the order link existed remain readable. New checkout redemptions always
     * set this field and are protected by the V11 foreign-key/unique index.
     */
    @Column(name = "order_id", length = 64)
    private String orderId;

    @Column(name = "subtotal", nullable = false, precision = 15, scale = 2)
    private BigDecimal subtotal;

    @Column(name = "so_tien_giam", nullable = false, precision = 15, scale = 2)
    private BigDecimal discountAmount;

    @Column(name = "ngay_su_dung", nullable = false)
    private LocalDateTime redeemedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAssignmentId() {
        return assignmentId;
    }

    public void setAssignmentId(String assignmentId) {
        this.assignmentId = assignmentId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getVoucherCode() {
        return voucherCode;
    }

    public void setVoucherCode(String voucherCode) {
        this.voucherCode = voucherCode;
    }

    public String getOrderId() {
        return orderId;
    }

    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public BigDecimal getSubtotal() {
        return subtotal;
    }

    public void setSubtotal(BigDecimal subtotal) {
        this.subtotal = subtotal;
    }

    public BigDecimal getDiscountAmount() {
        return discountAmount;
    }

    public void setDiscountAmount(BigDecimal discountAmount) {
        this.discountAmount = discountAmount;
    }

    public LocalDateTime getRedeemedAt() {
        return redeemedAt;
    }

    public void setRedeemedAt(LocalDateTime redeemedAt) {
        this.redeemedAt = redeemedAt;
    }
}
