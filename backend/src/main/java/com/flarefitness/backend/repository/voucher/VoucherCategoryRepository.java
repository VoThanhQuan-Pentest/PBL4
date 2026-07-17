package com.flarefitness.backend.repository.voucher;

import com.flarefitness.backend.entity.voucher.VoucherCategory;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface VoucherCategoryRepository extends JpaRepository<VoucherCategory, String> {

    List<VoucherCategory> findByVoucherCodeInOrderByVoucherCodeAscCategoryLabelAsc(Collection<String> voucherCodes);

    @Modifying
    @Query("delete from VoucherCategory category where category.voucherCode = :voucherCode")
    void deleteByVoucherCode(@Param("voucherCode") String voucherCode);
}
