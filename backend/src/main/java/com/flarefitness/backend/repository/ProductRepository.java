package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.Product;
import jakarta.persistence.LockModeType;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ProductRepository extends JpaRepository<Product, String> {

    @Query("select p from Product p where p.deleted = false order by p.createdAt desc")
    List<Product> findAllByOrderByCreatedAtDesc();

    @Query("select p from Product p where p.deleted = false order by p.createdAt desc")
    Page<Product> findAllByOrderByCreatedAtDesc(Pageable pageable);

    @Query("select p from Product p where lower(p.sku) = lower(:sku) and p.deleted = false")
    Optional<Product> findBySkuIgnoreCase(@Param("sku") String sku);

    @Query("select p from Product p where p.id = :id and p.deleted = false")
    Optional<Product> findActiveById(@Param("id") String id);

    @Query("""
            select p from Product p
            where lower(p.danhMuc) = lower(:category)
              and (p.deleted = false or p.deleted is null)
            order by p.createdAt desc
            """)
    List<Product> findActiveByCategoryIgnoreCase(@Param("category") String category, Pageable pageable);

    @Query("""
            select p from Product p
            where lower(p.thuongHieu) = lower(:brand)
              and (p.deleted = false or p.deleted is null)
            order by p.createdAt desc
            """)
    List<Product> findActiveByBrandIgnoreCase(@Param("brand") String brand, Pageable pageable);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from Product p where p.id in :ids and p.deleted = false order by p.id")
    List<Product> findAllByIdForUpdate(@Param("ids") Collection<String> ids);

    @Query(value = """
            select p.*
            from tbl_san_pham p
            where p.is_deleted = 0
              and (:category is null or p.danh_muc = :category)
              and (:brand is null or p.thuong_hieu = :brand)
              and (:status is null or p.trang_thai = :status)
              and (:minPrice is null or p.gia_ban >= :minPrice)
              and (:maxPrice is null or p.gia_ban <= :maxPrice)
              and (:inStockOnly = 0 or p.ton_kho > 0)
              and (:searchQuery is null or match(p.ten_san_pham, p.sku, p.danh_muc, p.thuong_hieu) against (:searchQuery in boolean mode))
            order by p.ngay_tao desc, p.id desc
            """,
            countQuery = """
            select count(*)
            from tbl_san_pham p
            where p.is_deleted = 0
              and (:category is null or p.danh_muc = :category)
              and (:brand is null or p.thuong_hieu = :brand)
              and (:status is null or p.trang_thai = :status)
              and (:minPrice is null or p.gia_ban >= :minPrice)
              and (:maxPrice is null or p.gia_ban <= :maxPrice)
              and (:inStockOnly = 0 or p.ton_kho > 0)
              and (:searchQuery is null or match(p.ten_san_pham, p.sku, p.danh_muc, p.thuong_hieu) against (:searchQuery in boolean mode))
            """,
            nativeQuery = true)
    Page<Product> searchProducts(
            @Param("searchQuery") String searchQuery,
            @Param("category") String category,
            @Param("brand") String brand,
            @Param("status") String status,
            @Param("minPrice") BigDecimal minPrice,
            @Param("maxPrice") BigDecimal maxPrice,
            @Param("inStockOnly") int inStockOnly,
            Pageable pageable
    );

    @Query(value = """
            select p.*
            from tbl_san_pham p
            where p.is_deleted = 0
              and (:category is null or p.danh_muc = :category)
              and (:brand is null or p.thuong_hieu = :brand)
              and (:status is null or p.trang_thai = :status)
              and (:minPrice is null or p.gia_ban >= :minPrice)
              and (:maxPrice is null or p.gia_ban <= :maxPrice)
              and (:inStockOnly = 0 or p.ton_kho > 0)
              and (:searchPattern is null
                   or p.ten_san_pham like :searchPattern
                   or p.sku like :searchPattern
                   or p.danh_muc like :searchPattern
                   or p.thuong_hieu like :searchPattern)
            order by p.ngay_tao desc, p.id desc
            """,
            countQuery = """
            select count(*)
            from tbl_san_pham p
            where p.is_deleted = 0
              and (:category is null or p.danh_muc = :category)
              and (:brand is null or p.thuong_hieu = :brand)
              and (:status is null or p.trang_thai = :status)
              and (:minPrice is null or p.gia_ban >= :minPrice)
              and (:maxPrice is null or p.gia_ban <= :maxPrice)
              and (:inStockOnly = 0 or p.ton_kho > 0)
              and (:searchPattern is null
                   or p.ten_san_pham like :searchPattern
                   or p.sku like :searchPattern
                   or p.danh_muc like :searchPattern
                   or p.thuong_hieu like :searchPattern)
            """,
            nativeQuery = true)
    Page<Product> searchProductsFallback(
            @Param("searchPattern") String searchPattern,
            @Param("category") String category,
            @Param("brand") String brand,
            @Param("status") String status,
            @Param("minPrice") BigDecimal minPrice,
            @Param("maxPrice") BigDecimal maxPrice,
            @Param("inStockOnly") int inStockOnly,
            Pageable pageable
    );
}
