package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.ProductVariant;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ProductVariantRepository extends JpaRepository<ProductVariant, String> {

    @Query("""
            select variant from ProductVariant variant
            where variant.productId in :productIds
              and (variant.deleted = false or variant.deleted is null)
            order by variant.productId, variant.size, variant.mau, variant.id
            """)
    List<ProductVariant> findActiveByProductIdIn(@Param("productIds") Collection<String> productIds);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select variant from ProductVariant variant
            where variant.id in :variantIds
              and (variant.deleted = false or variant.deleted is null)
            order by variant.id
            """)
    List<ProductVariant> findActiveByIdInForUpdate(@Param("variantIds") Collection<String> variantIds);
}
