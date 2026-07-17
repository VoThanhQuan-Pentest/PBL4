package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.ProductReview;
import com.flarefitness.backend.entity.Order;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ProductReviewRepository extends JpaRepository<ProductReview, String> {

    boolean existsByUserIdAndProductIdAndOrderId(String userId, String productId, String orderId);

    Page<ProductReview> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<ProductReview> findByProductIdAndStatusOrderByCreatedAtDesc(String productId, String status, Pageable pageable);

    @Query("""
            select o from Order o
            where o.userId = :userId
              and (o.deleted = false or o.deleted is null)
              and o.trangThaiDon in :deliveredStatuses
              and exists (
                  select item.id from OrderItem item
                  where item.orderId = o.id and item.productId = :productId
              )
              and not exists (
                  select review.id from ProductReview review
                  where review.orderId = o.id
                    and review.productId = :productId
                    and review.userId = :userId
              )
            order by o.createdAt desc
            """)
    List<Order> findFirstReviewableOrderForProduct(
            @Param("userId") String userId,
            @Param("productId") String productId,
            @Param("deliveredStatuses") Collection<String> deliveredStatuses,
            Pageable pageable
    );
}
