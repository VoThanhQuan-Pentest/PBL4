-- Keep OFFSET pagination bounded at the database as well as at the API.
-- Both indexes are conditional so installations upgraded from the historical
-- Docker schema are safe to migrate without modifying user or product data.
DROP PROCEDURE IF EXISTS ff_add_pagination_index_if_missing;
DELIMITER $$
CREATE PROCEDURE ff_add_pagination_index_if_missing(
    IN table_name_value VARCHAR(64),
    IN index_name_value VARCHAR(64),
    IN index_definition VARCHAR(400)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = table_name_value
          AND index_name = index_name_value
    ) THEN
        SET @statement = CONCAT('ALTER TABLE `', table_name_value, '` ADD ', index_definition);
        PREPARE stmt FROM @statement;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$
DELIMITER ;

-- Admin users are displayed by name, while keeping deleted accounts visible
-- for audit purposes.
CALL ff_add_pagination_index_if_missing(
    'tbl_nguoi_dung',
    'idx_tbl_nguoi_dung_ho_ten_id',
    'KEY `idx_tbl_nguoi_dung_ho_ten_id` (`ho_ten`, `id`)'
);

-- Catalog pages filter soft-deleted products then order by creation time/id.
CALL ff_add_pagination_index_if_missing(
    'tbl_san_pham',
    'idx_tbl_san_pham_active_created',
    'KEY `idx_tbl_san_pham_active_created` (`is_deleted`, `ngay_tao`, `id`)'
);

DROP PROCEDURE ff_add_pagination_index_if_missing;
