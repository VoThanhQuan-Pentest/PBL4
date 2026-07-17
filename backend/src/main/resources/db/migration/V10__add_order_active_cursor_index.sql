-- The cursor endpoints and the bounded compatibility endpoints both filter
-- soft-deleted orders before sorting by creation time/id. Historical schemas
-- have user/customer cursor indexes, but not this global active-order index.
DROP PROCEDURE IF EXISTS ff_add_order_cursor_index_if_missing;
DELIMITER $$
CREATE PROCEDURE ff_add_order_cursor_index_if_missing()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'tbl_don_hang'
          AND index_name = 'idx_tbl_don_hang_active_cursor'
    ) THEN
        ALTER TABLE tbl_don_hang
            ADD KEY idx_tbl_don_hang_active_cursor (is_deleted, ngay_tao, id);
    END IF;
END$$
DELIMITER ;

CALL ff_add_order_cursor_index_if_missing();
DROP PROCEDURE ff_add_order_cursor_index_if_missing;
