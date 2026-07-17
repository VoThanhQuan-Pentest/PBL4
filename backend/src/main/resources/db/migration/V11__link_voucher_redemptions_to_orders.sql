-- Existing redemptions predate the order link and intentionally remain NULL.
-- Every redemption created by the current checkout path has an order id; the
-- FK and unique key make that link durable and prevent two voucher redemptions
-- from being attached to the same order.
DROP PROCEDURE IF EXISTS ff_link_voucher_redemptions_to_orders;
DELIMITER $$
CREATE PROCEDURE ff_link_voucher_redemptions_to_orders()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = 'tbl_su_dung_ma_giam_gia'
          AND column_name = 'order_id'
    ) THEN
        ALTER TABLE tbl_su_dung_ma_giam_gia
            ADD COLUMN order_id VARCHAR(64) NULL AFTER voucher_code;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'tbl_su_dung_ma_giam_gia'
          AND index_name = 'uk_voucher_redemption_order'
    ) THEN
        ALTER TABLE tbl_su_dung_ma_giam_gia
            ADD UNIQUE KEY uk_voucher_redemption_order (order_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.referential_constraints
        WHERE constraint_schema = DATABASE()
          AND table_name = 'tbl_su_dung_ma_giam_gia'
          AND constraint_name = 'fk_voucher_redemption_order'
    ) THEN
        ALTER TABLE tbl_su_dung_ma_giam_gia
            ADD CONSTRAINT fk_voucher_redemption_order
            FOREIGN KEY (order_id) REFERENCES tbl_don_hang (id)
            ON UPDATE CASCADE ON DELETE RESTRICT;
    END IF;
END$$
DELIMITER ;

CALL ff_link_voucher_redemptions_to_orders();
DROP PROCEDURE ff_link_voucher_redemptions_to_orders;
