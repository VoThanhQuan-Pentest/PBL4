package com.flarefitness.backend.repository.voucher;

import com.flarefitness.backend.entity.voucher.VoucherRedemption;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VoucherRedemptionRepository extends JpaRepository<VoucherRedemption, String> {
}
