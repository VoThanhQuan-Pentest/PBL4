SET NAMES utf8mb4;
USE flare_fitness;

DROP PROCEDURE IF EXISTS migrate_review_order_id;

DELIMITER $$
CREATE PROCEDURE migrate_review_order_id()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_danh_gia_san_pham'
          AND COLUMN_NAME = 'order_id'
    ) THEN
        ALTER TABLE tbl_danh_gia_san_pham
            ADD COLUMN order_id VARCHAR(64) NULL AFTER product_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_danh_gia_san_pham'
          AND INDEX_NAME = 'idx_tbl_danh_gia_order'
    ) THEN
        ALTER TABLE tbl_danh_gia_san_pham
            ADD INDEX idx_tbl_danh_gia_order (order_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_danh_gia_san_pham'
          AND CONSTRAINT_NAME = 'uk_tbl_danh_gia_order_product_user'
    ) THEN
        ALTER TABLE tbl_danh_gia_san_pham
            ADD UNIQUE KEY uk_tbl_danh_gia_order_product_user (order_id, product_id, user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_danh_gia_san_pham'
          AND CONSTRAINT_NAME = 'fk_tbl_danh_gia_order'
    ) THEN
        ALTER TABLE tbl_danh_gia_san_pham
            ADD CONSTRAINT fk_tbl_danh_gia_order
            FOREIGN KEY (order_id) REFERENCES tbl_don_hang (id)
            ON UPDATE CASCADE ON DELETE CASCADE;
    END IF;
END$$
DELIMITER ;

CALL migrate_review_order_id();

DROP PROCEDURE IF EXISTS migrate_review_order_id;
