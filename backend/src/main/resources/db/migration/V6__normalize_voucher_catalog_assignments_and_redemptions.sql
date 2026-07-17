-- Voucher data used to live in mutable sync-state JSON.  Keep that state intact for
-- forensic/rollback purposes, but move all server-authoritative voucher data into
-- relational tables with constraints that also protect concurrent checkout requests.

CREATE TABLE IF NOT EXISTS tbl_ma_giam_gia (
    ma VARCHAR(64) NOT NULL,
    nhan VARCHAR(255) NOT NULL,
    ty_le_giam DECIMAL(7,4) NOT NULL,
    gia_tri_don_toi_thieu DECIMAL(15,2) NOT NULL DEFAULT 0,
    giam_toi_da DECIMAL(15,2) NOT NULL DEFAULT 0,
    ngay_het_han DATE NULL,
    trang_thai VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ma),
    KEY idx_voucher_status_expiry (trang_thai, ngay_het_han)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tbl_danh_muc_ma_giam_gia (
    id VARCHAR(64) NOT NULL,
    voucher_code VARCHAR(64) NOT NULL,
    category_key VARCHAR(160) NOT NULL,
    category_label VARCHAR(100) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_voucher_category (voucher_code, category_key),
    KEY idx_voucher_category_voucher (voucher_code),
    CONSTRAINT fk_voucher_category_voucher FOREIGN KEY (voucher_code) REFERENCES tbl_ma_giam_gia (ma)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tbl_phan_bo_ma_giam_gia (
    id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    voucher_code VARCHAR(64) NOT NULL,
    so_luong INT NOT NULL,
    so_luong_da_dung INT NOT NULL DEFAULT 0,
    trang_thai VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    ngay_cap DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_voucher_assignment_user_code (user_id, voucher_code),
    KEY idx_voucher_assignment_user_updated (user_id, ngay_cap_nhat),
    KEY idx_voucher_assignment_voucher (voucher_code),
    CONSTRAINT fk_voucher_assignment_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_voucher_assignment_voucher FOREIGN KEY (voucher_code) REFERENCES tbl_ma_giam_gia (ma)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tbl_su_dung_ma_giam_gia (
    id VARCHAR(64) NOT NULL,
    assignment_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    voucher_code VARCHAR(64) NOT NULL,
    subtotal DECIMAL(15,2) NOT NULL,
    so_tien_giam DECIMAL(15,2) NOT NULL,
    ngay_su_dung DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_voucher_redemption_assignment (assignment_id, ngay_su_dung),
    KEY idx_voucher_redemption_user (user_id, ngay_su_dung),
    KEY idx_voucher_redemption_code (voucher_code, ngay_su_dung),
    CONSTRAINT fk_voucher_redemption_assignment FOREIGN KEY (assignment_id) REFERENCES tbl_phan_bo_ma_giam_gia (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_voucher_redemption_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_voucher_redemption_voucher FOREIGN KEY (voucher_code) REFERENCES tbl_ma_giam_gia (ma)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Import valid legacy managed-vouchers entries first. Invalid or malformed JSON is
-- deliberately ignored and remains untouched in tbl_sync_state for manual review.
INSERT INTO tbl_ma_giam_gia (
    ma, nhan, ty_le_giam, gia_tri_don_toi_thieu, giam_toi_da, ngay_het_han,
    trang_thai, ngay_tao, ngay_cap_nhat
)
SELECT legacy.code,
       legacy.label,
       legacy.percent,
       legacy.min_order,
       legacy.max_discount,
       legacy.expires_at,
       legacy.status,
       NOW(),
       NOW()
FROM (
    SELECT UPPER(TRIM(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.code')))) AS code,
           LEFT(TRIM(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.label'))), 255) AS label,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.percent'))
                   REGEXP '^(0|0\\.[0-9]{1,4}|1(\\.0{1,4})?)$'
                   THEN CAST(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.percent')) AS DECIMAL(7,4))
               ELSE 0
           END AS percent,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.minOrder'))
                   REGEXP '^[0-9]{1,13}(\\.[0-9]{1,2})?$'
                   THEN CAST(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.minOrder')) AS DECIMAL(15,2))
               ELSE 0
           END AS min_order,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.maxDiscount'))
                   REGEXP '^[0-9]{1,13}(\\.[0-9]{1,2})?$'
                   THEN CAST(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.maxDiscount')) AS DECIMAL(15,2))
               ELSE 0
           END AS max_discount,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.expiresAt')) REGEXP '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
                   THEN STR_TO_DATE(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.expiresAt')), '%Y-%m-%d')
               ELSE NULL
           END AS expires_at,
           CASE LOWER(TRIM(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.status'))))
               WHEN 'active' THEN 'ACTIVE'
               WHEN 'hoạt động' THEN 'ACTIVE'
               WHEN 'đang mở' THEN 'ACTIVE'
               WHEN 'disabled' THEN 'DISABLED'
               WHEN 'tạm khóa' THEN 'DISABLED'
               WHEN 'deleted' THEN 'DELETED'
               WHEN 'đã xóa' THEN 'DELETED'
               ELSE 'DISABLED'
           END AS status
    FROM tbl_sync_state state
    CROSS JOIN JSON_TABLE(
        CASE WHEN JSON_VALID(state.payload) THEN state.payload ELSE '[]' END,
        '$[*]' COLUMNS (document JSON PATH '$')
    ) item
    WHERE state.scope = 'APP'
      AND state.owner_id IS NULL
      AND state.state_key = 'managed-vouchers'
) legacy
WHERE CHAR_LENGTH(legacy.code) BETWEEN 2 AND 64
  AND legacy.code REGEXP '^[A-Z0-9_-]+$'
  AND CHAR_LENGTH(legacy.label) BETWEEN 1 AND 255
  AND legacy.percent > 0 AND legacy.percent <= 1
  AND legacy.min_order >= 0 AND legacy.max_discount >= 0
ON DUPLICATE KEY UPDATE
    nhan = VALUES(nhan),
    ty_le_giam = VALUES(ty_le_giam),
    gia_tri_don_toi_thieu = VALUES(gia_tri_don_toi_thieu),
    giam_toi_da = VALUES(giam_toi_da),
    ngay_het_han = VALUES(ngay_het_han),
    trang_thai = VALUES(trang_thai),
    ngay_cap_nhat = VALUES(ngay_cap_nhat);

-- Legacy category arrays are imported when present. A voucher with no persisted
-- category is interpreted as "Tất cả" by the application.
INSERT INTO tbl_danh_muc_ma_giam_gia (id, voucher_code, category_key, category_label)
SELECT CONCAT('vcat-', UUID()), legacy.code,
       LEFT(LOWER(TRIM(category.label)), 160),
       LEFT(TRIM(category.label), 100)
FROM (
    SELECT UPPER(TRIM(JSON_UNQUOTE(JSON_EXTRACT(item.document, '$.code')))) AS code,
           item.document
    FROM tbl_sync_state state
    CROSS JOIN JSON_TABLE(
        CASE WHEN JSON_VALID(state.payload) THEN state.payload ELSE '[]' END,
        '$[*]' COLUMNS (document JSON PATH '$')
    ) item
    WHERE state.scope = 'APP'
      AND state.owner_id IS NULL
      AND state.state_key = 'managed-vouchers'
) legacy
CROSS JOIN JSON_TABLE(
    CASE
        WHEN JSON_TYPE(JSON_EXTRACT(legacy.document, '$.categories')) = 'ARRAY'
            THEN JSON_EXTRACT(legacy.document, '$.categories')
        ELSE JSON_ARRAY('Tất cả')
    END,
    '$[*]' COLUMNS (label VARCHAR(100) PATH '$')
) category
JOIN tbl_ma_giam_gia voucher ON voucher.ma = legacy.code COLLATE utf8mb4_unicode_ci
WHERE CHAR_LENGTH(TRIM(category.label)) > 0
ON DUPLICATE KEY UPDATE category_label = VALUES(category_label);

-- Preserve previously granted valid legacy vouchers. The original sync-state rows
-- are not removed or changed. Unknown/deleted users and unknown voucher codes are
-- ignored rather than creating orphaned grants.
INSERT INTO tbl_phan_bo_ma_giam_gia (
    id, user_id, voucher_code, so_luong, so_luong_da_dung, trang_thai, ngay_cap, ngay_tao, ngay_cap_nhat
)
SELECT CONCAT('vassign-', UUID()), legacy.user_id, legacy.code,
       legacy.quantity,
       LEAST(legacy.used_quantity, legacy.quantity),
       'ACTIVE',
       NOW(), NOW(), NOW()
FROM (
    SELECT state.owner_id AS user_id,
           UPPER(TRIM(JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.code')))) AS code,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.quantity')) REGEXP '^[0-9]+$'
                    AND CHAR_LENGTH(JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.quantity'))) <= 10
                   THEN GREATEST(1, LEAST(2147483647,
                       CAST(JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.quantity')) AS UNSIGNED)))
               ELSE 1
           END AS quantity,
           CASE
               WHEN JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.used')) REGEXP '^[0-9]+$'
                    AND CHAR_LENGTH(JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.used'))) <= 10
                   THEN LEAST(2147483647,
                       CAST(JSON_UNQUOTE(JSON_EXTRACT(grant_item.document, '$.used')) AS UNSIGNED))
               ELSE 0
           END AS used_quantity
    FROM tbl_sync_state state
    CROSS JOIN JSON_TABLE(
        CASE WHEN JSON_VALID(state.payload) THEN state.payload ELSE '{}' END,
        '$.grants.*' COLUMNS (document JSON PATH '$')
    ) grant_item
    WHERE state.scope = 'USER'
      AND state.owner_id IS NOT NULL
      AND state.state_key = 'voucher-assignments'
) legacy
JOIN tbl_nguoi_dung user_account ON user_account.id = legacy.user_id
JOIN tbl_ma_giam_gia voucher ON voucher.ma = legacy.code COLLATE utf8mb4_unicode_ci
WHERE CHAR_LENGTH(legacy.code) BETWEEN 2 AND 64
  AND legacy.code REGEXP '^[A-Z0-9_-]+$'
ON DUPLICATE KEY UPDATE
    so_luong = GREATEST(so_luong, VALUES(so_luong)),
    so_luong_da_dung = LEAST(
        GREATEST(so_luong_da_dung, VALUES(so_luong_da_dung)),
        GREATEST(so_luong, VALUES(so_luong))
    ),
    ngay_cap_nhat = VALUES(ngay_cap_nhat);

-- Older clients sometimes persisted only codes[] without grant metadata.
INSERT INTO tbl_phan_bo_ma_giam_gia (
    id, user_id, voucher_code, so_luong, so_luong_da_dung, trang_thai, ngay_cap, ngay_tao, ngay_cap_nhat
)
SELECT CONCAT('vassign-', UUID()), state.owner_id,
       UPPER(TRIM(code_item.code)), 1, 0, 'ACTIVE', NOW(), NOW(), NOW()
FROM tbl_sync_state state
CROSS JOIN JSON_TABLE(
    CASE WHEN JSON_VALID(state.payload) THEN state.payload ELSE '{}' END,
    '$.codes[*]' COLUMNS (code VARCHAR(64) PATH '$')
) code_item
JOIN tbl_nguoi_dung user_account ON user_account.id = state.owner_id
JOIN tbl_ma_giam_gia voucher ON voucher.ma =
    CONVERT(UPPER(TRIM(code_item.code)) USING utf8mb4) COLLATE utf8mb4_unicode_ci
WHERE state.scope = 'USER'
  AND state.owner_id IS NOT NULL
  AND state.state_key = 'voucher-assignments'
  AND CHAR_LENGTH(UPPER(TRIM(code_item.code))) BETWEEN 2 AND 64
  AND UPPER(TRIM(code_item.code)) REGEXP '^[A-Z0-9_-]+$'
ON DUPLICATE KEY UPDATE ngay_cap_nhat = VALUES(ngay_cap_nhat);
