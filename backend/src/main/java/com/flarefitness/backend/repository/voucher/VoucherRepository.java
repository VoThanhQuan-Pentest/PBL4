package com.flarefitness.backend.repository.voucher;

import com.flarefitness.backend.entity.voucher.Voucher;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface VoucherRepository extends JpaRepository<Voucher, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select voucher from Voucher voucher where voucher.code = :code")
    Optional<Voucher> findByCodeForUpdate(@Param("code") String code);

    @Query("select voucher from Voucher voucher where voucher.status <> 'DELETED' order by voucher.code asc")
    List<Voucher> findAllVisible();
}
