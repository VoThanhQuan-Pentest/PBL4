SET NAMES utf8mb4;
USE flare_fitness;

DROP PROCEDURE IF EXISTS migrate_customer_phone_unique;

DELIMITER $$
CREATE PROCEDURE migrate_customer_phone_unique()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_khach_hang'
          AND COLUMN_NAME = 'sdt_active'
    ) THEN
        ALTER TABLE tbl_khach_hang
            ADD COLUMN sdt_active VARCHAR(30) GENERATED ALWAYS AS (
                CASE
                    WHEN is_deleted = 0 THEN
                        CASE WHEN LEFT(sdt, 3) = '+84' THEN CONCAT('0', SUBSTRING(sdt, 4)) ELSE sdt END
                    ELSE NULL
                END
            ) STORED AFTER sdt;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'tbl_khach_hang'
          AND INDEX_NAME = 'uk_tbl_khach_hang_sdt_active'
    ) THEN
        ALTER TABLE tbl_khach_hang
            ADD UNIQUE KEY uk_tbl_khach_hang_sdt_active (sdt_active);
    END IF;
END$$
DELIMITER ;

CALL migrate_customer_phone_unique();

DROP PROCEDURE IF EXISTS migrate_customer_phone_unique;
