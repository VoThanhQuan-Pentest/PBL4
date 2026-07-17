-- Reconcile installations that were previously initialized by db-init scripts.
-- Every statement is safe to run on a database already containing production data.
CREATE TABLE IF NOT EXISTS tbl_ho_tro_khach_hang (
    id VARCHAR(64) PRIMARY KEY,
    customer_user_id VARCHAR(64) NOT NULL,
    trang_thai VARCHAR(50) NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_support_thread_customer (customer_user_id),
    INDEX idx_support_thread_updated (ngay_cap_nhat)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tbl_tin_nhan_ho_tro (
    id VARCHAR(64) PRIMARY KEY,
    thread_id VARCHAR(64) NOT NULL,
    sender_type VARCHAR(20) NOT NULL,
    sender_user_id VARCHAR(64) NULL,
    noi_dung TEXT NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_support_message_thread_created (thread_id, ngay_tao)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Preserve conversations while merging historical duplicate customer threads.
UPDATE tbl_tin_nhan_ho_tro AS message
JOIN tbl_ho_tro_khach_hang AS duplicate_thread ON duplicate_thread.id = message.thread_id
JOIN (
    SELECT customer_user_id, MIN(id) AS canonical_thread_id
    FROM tbl_ho_tro_khach_hang
    GROUP BY customer_user_id
    HAVING COUNT(*) > 1
) AS duplicate_group ON duplicate_group.customer_user_id = duplicate_thread.customer_user_id
SET message.thread_id = duplicate_group.canonical_thread_id
WHERE duplicate_thread.id <> duplicate_group.canonical_thread_id;

DELETE duplicate_thread
FROM tbl_ho_tro_khach_hang AS duplicate_thread
JOIN (
    SELECT customer_user_id, MIN(id) AS canonical_thread_id
    FROM tbl_ho_tro_khach_hang
    GROUP BY customer_user_id
    HAVING COUNT(*) > 1
) AS duplicate_group ON duplicate_group.customer_user_id = duplicate_thread.customer_user_id
WHERE duplicate_thread.id <> duplicate_group.canonical_thread_id;

DELIMITER $$
CREATE PROCEDURE add_index_if_missing(
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

CALL add_index_if_missing('tbl_ho_tro_khach_hang', 'uk_support_thread_customer',
    'UNIQUE KEY `uk_support_thread_customer` (`customer_user_id`)');
CALL add_index_if_missing('tbl_tin_nhan_ho_tro', 'idx_support_message_thread_created',
    'KEY `idx_support_message_thread_created` (`thread_id`, `ngay_tao`)');
CALL add_index_if_missing('tbl_su_kien_hanh_vi_nguoi_dung', 'idx_behavior_event_time',
    'KEY `idx_behavior_event_time` (`event_type`, `ngay_tao`)');
CALL add_index_if_missing('tbl_su_kien_hanh_vi_nguoi_dung', 'idx_behavior_product_time',
    'KEY `idx_behavior_product_time` (`product_id`, `ngay_tao`)');
DROP PROCEDURE add_index_if_missing;
