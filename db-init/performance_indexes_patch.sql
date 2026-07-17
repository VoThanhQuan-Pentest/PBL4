DELIMITER $$

DROP PROCEDURE IF EXISTS add_index_if_missing$$
CREATE PROCEDURE add_index_if_missing(
    IN table_name_value VARCHAR(128),
    IN index_name_value VARCHAR(128),
    IN alter_statement_value TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = table_name_value
          AND index_name = index_name_value
    ) THEN
        SET @alter_statement = alter_statement_value;
        PREPARE statement_to_run FROM @alter_statement;
        EXECUTE statement_to_run;
        DEALLOCATE PREPARE statement_to_run;
    END IF;
END$$

CALL add_index_if_missing(
    'tbl_san_pham',
    'idx_tbl_san_pham_filter',
    'ALTER TABLE tbl_san_pham ADD INDEX idx_tbl_san_pham_filter (danh_muc, thuong_hieu, trang_thai, gia_ban)'
)$$
CALL add_index_if_missing(
    'tbl_san_pham',
    'ftx_tbl_san_pham_search',
    'ALTER TABLE tbl_san_pham ADD FULLTEXT INDEX ftx_tbl_san_pham_search (ten_san_pham, sku, danh_muc, thuong_hieu)'
)$$
CALL add_index_if_missing(
    'tbl_don_hang',
    'idx_tbl_don_hang_user_cursor',
    'ALTER TABLE tbl_don_hang ADD INDEX idx_tbl_don_hang_user_cursor (user_id, ngay_tao, id)'
)$$
CALL add_index_if_missing(
    'tbl_don_hang',
    'idx_tbl_don_hang_customer_cursor',
    'ALTER TABLE tbl_don_hang ADD INDEX idx_tbl_don_hang_customer_cursor (customer_id, ngay_tao, id)'
)$$
CALL add_index_if_missing(
    'tbl_don_hang',
    'idx_tbl_don_hang_status_cursor',
    'ALTER TABLE tbl_don_hang ADD INDEX idx_tbl_don_hang_status_cursor (trang_thai_don, ngay_tao, id)'
)$$
CALL add_index_if_missing(
    'tbl_don_hang',
    'idx_tbl_don_hang_user_status_cursor',
    'ALTER TABLE tbl_don_hang ADD INDEX idx_tbl_don_hang_user_status_cursor (user_id, trang_thai_don, ngay_tao, id)'
)$$
CALL add_index_if_missing(
    'tbl_don_hang',
    'idx_tbl_don_hang_paid_date',
    'ALTER TABLE tbl_don_hang ADD INDEX idx_tbl_don_hang_paid_date (da_thanh_toan, ngay_dat)'
)$$
CALL add_index_if_missing(
    'tbl_chi_tiet_don_hang',
    'idx_tbl_chi_tiet_don_hang_order_product',
    'ALTER TABLE tbl_chi_tiet_don_hang ADD INDEX idx_tbl_chi_tiet_don_hang_order_product (order_id, product_id)'
)$$
CALL add_index_if_missing(
    'tbl_danh_gia_san_pham',
    'idx_tbl_danh_gia_product_status_created',
    'ALTER TABLE tbl_danh_gia_san_pham ADD INDEX idx_tbl_danh_gia_product_status_created (product_id, status, ngay_tao)'
)$$
CALL add_index_if_missing(
    'tbl_danh_gia_san_pham',
    'idx_tbl_danh_gia_user_product_order',
    'ALTER TABLE tbl_danh_gia_san_pham ADD INDEX idx_tbl_danh_gia_user_product_order (user_id, product_id, order_id)'
)$$
CALL add_index_if_missing(
    'tbl_su_kien_hanh_vi_nguoi_dung',
    'idx_behavior_created_time',
    'ALTER TABLE tbl_su_kien_hanh_vi_nguoi_dung ADD INDEX idx_behavior_created_time (ngay_tao)'
)$$

DROP PROCEDURE add_index_if_missing$$

DELIMITER ;
