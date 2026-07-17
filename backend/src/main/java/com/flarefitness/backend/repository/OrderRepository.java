package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.Order;
import jakarta.persistence.LockModeType;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OrderRepository extends JpaRepository<Order, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select o from Order o where o.id = :id")
    Optional<Order> findByIdForUpdate(@Param("id") String id);

    @Query("select o from Order o where (o.deleted = false or o.deleted is null) order by o.createdAt desc")
    List<Order> findAllByOrderByCreatedAtDesc();

    @Query("select o from Order o where o.userId = :userId and (o.deleted = false or o.deleted is null) order by o.createdAt desc")
    List<Order> findByUserIdOrderByCreatedAtDesc(@Param("userId") String userId);

    @Query("select o from Order o where o.customerId = :customerId and (o.deleted = false or o.deleted is null) order by o.createdAt desc")
    List<Order> findByCustomerIdOrderByCreatedAtDesc(@Param("customerId") String customerId);

    @Query("select count(o) > 0 from Order o where o.customerId = :customerId and (o.deleted = false or o.deleted is null)")
    boolean existsByCustomerId(@Param("customerId") String customerId);

    @Query("""
            select coalesce(sum(o.tongTien), 0)
            from Order o
            where (o.deleted = false or o.deleted is null)
              and o.daThanhToan = true
              and o.ngayDat between :fromDate and :toDate
            """)
    BigDecimal sumPaidRevenueBetween(@Param("fromDate") LocalDate fromDate, @Param("toDate") LocalDate toDate);

    @Query("select o from Order o where o.maDon = :maDon and (o.deleted = false or o.deleted is null)")
    Optional<Order> findByMaDon(@Param("maDon") String maDon);

    @Query("""
            select o from Order o
            where o.userId = :userId
               or (:customerId is not null and o.customerId = :customerId)
            """)
    List<Order> findForSoftDelete(@Param("userId") String userId, @Param("customerId") String customerId);

    @Query("""
            select o from Order o
            where (o.deleted = false or o.deleted is null)
              and (:before is null
                   or o.createdAt < :before
                   or (o.createdAt = :before and o.id < :beforeId))
            order by o.createdAt desc, o.id desc
            """)
    List<Order> findPageBefore(
            @Param("before") LocalDateTime before,
            @Param("beforeId") String beforeId,
            Pageable pageable
    );

    @Query("""
            select o from Order o
            where (o.deleted = false or o.deleted is null)
              and (o.userId = :userId or (:customerId is not null and o.customerId = :customerId))
              and (:before is null
                   or o.createdAt < :before
                   or (o.createdAt = :before and o.id < :beforeId))
            order by o.createdAt desc, o.id desc
            """)
    List<Order> findCustomerPageBefore(
            @Param("userId") String userId,
            @Param("customerId") String customerId,
            @Param("before") LocalDateTime before,
            @Param("beforeId") String beforeId,
            Pageable pageable
    );
}
