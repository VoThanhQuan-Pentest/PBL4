-- Profile APIs accept an omitted phone. Only real, active phone numbers are unique.
-- Keep +84/0 equivalence and soft-delete semantics for nonempty values.
ALTER TABLE tbl_khach_hang
    DROP INDEX uk_tbl_khach_hang_sdt_active,
    MODIFY COLUMN sdt_active VARCHAR(30) GENERATED ALWAYS AS (
        CASE WHEN is_deleted = 0 AND TRIM(sdt) <> '' THEN
            CASE WHEN LEFT(sdt, 3) = '+84' THEN CONCAT('0', SUBSTRING(sdt, 4)) ELSE sdt END
        ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_tbl_khach_hang_sdt_active (sdt_active);
