package com.flarefitness.backend.repository.voucher;

import com.flarefitness.backend.entity.voucher.VoucherAssignment;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface VoucherAssignmentRepository extends JpaRepository<VoucherAssignment, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select assignment from VoucherAssignment assignment
            where assignment.userId = :userId and assignment.voucherCode = :voucherCode
            """)
    Optional<VoucherAssignment> findByUserIdAndVoucherCodeForUpdate(
            @Param("userId") String userId,
            @Param("voucherCode") String voucherCode
    );

    @Query("""
            select assignment from VoucherAssignment assignment
            where assignment.userId = :userId and assignment.status = 'ACTIVE'
            order by assignment.assignedAt desc, assignment.voucherCode asc
            """)
    List<VoucherAssignment> findActiveByUserIdOrderByAssignedAtDescVoucherCodeAsc(@Param("userId") String userId);
}
