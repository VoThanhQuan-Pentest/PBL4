-- Customer identity must be rooted in the immutable user id.  This migration
-- never guesses from a display name and it deliberately does not auto-link an
-- old e-mail address: historic records do not prove that the address was
-- verified by the current account owner.  Operations can review this table and
-- make an explicit, auditable decision without losing orders or profiles.
CREATE TABLE IF NOT EXISTS tbl_kiem_toan_lien_ket_khach_hang (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    customer_id VARCHAR(64) NOT NULL,
    candidate_user_id VARCHAR(64) NOT NULL DEFAULT '',
    reason VARCHAR(80) NOT NULL,
    detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    resolution_note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_customer_identity_review (customer_id, candidate_user_id, reason),
    KEY idx_customer_identity_review_open (resolved_at, detected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Empty strings were used by a few legacy imports and are not a valid identity.
UPDATE tbl_khach_hang
SET user_id = NULL
WHERE user_id IS NOT NULL AND TRIM(user_id) = '';

-- Record every duplicate before attempting to add the invariant.  We leave the
-- rows unchanged for manual review so their historic order/customer references
-- remain intact.
INSERT IGNORE INTO tbl_kiem_toan_lien_ket_khach_hang (customer_id, candidate_user_id, reason)
SELECT customer.id, customer.user_id, 'DUPLICATE_USER_ID'
FROM tbl_khach_hang AS customer
JOIN (
    SELECT user_id
    FROM tbl_khach_hang
    WHERE user_id IS NOT NULL
    GROUP BY user_id
    HAVING COUNT(*) > 1
) AS duplicates ON duplicates.user_id = customer.user_id;

-- Existing links which point to a removed/non-existent account are also kept
-- unchanged and sent to the review queue rather than being reassigned by name.
INSERT IGNORE INTO tbl_kiem_toan_lien_ket_khach_hang (customer_id, candidate_user_id, reason)
SELECT customer.id, customer.user_id, 'UNKNOWN_OR_DELETED_USER_ID'
FROM tbl_khach_hang AS customer
LEFT JOIN tbl_nguoi_dung AS user_account ON user_account.id = customer.user_id
WHERE customer.user_id IS NOT NULL
  AND (user_account.id IS NULL OR user_account.is_deleted = 1);

-- A non-linked profile needs an explicit identity proof.  Registration/profile
-- flows can link a uniquely verified address going forward; legacy data is
-- reviewed manually instead of allowing a same-name or unverified-email match.
INSERT IGNORE INTO tbl_kiem_toan_lien_ket_khach_hang (customer_id, candidate_user_id, reason)
SELECT customer.id, '', 'UNLINKED_REQUIRES_VERIFIED_IDENTITY'
FROM tbl_khach_hang AS customer
WHERE customer.is_deleted = 0
  AND customer.user_id IS NULL;

DELIMITER $$
CREATE PROCEDURE ff_add_customer_user_unique_if_safe()
BEGIN
    -- Do not fail a production migration merely because a legacy database has
    -- conflicts.  The audit rows above make the exception visible; after they
    -- are resolved, this same invariant can be applied in the follow-up change.
    IF NOT EXISTS (
        SELECT 1
        FROM tbl_khach_hang
        WHERE user_id IS NOT NULL
        GROUP BY user_id
        HAVING COUNT(*) > 1
    )
    AND NOT EXISTS (
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'tbl_khach_hang'
          AND column_name = 'user_id'
          AND non_unique = 0
    ) THEN
        ALTER TABLE tbl_khach_hang
            ADD UNIQUE KEY uk_tbl_khach_hang_user_id (user_id);
    END IF;
END$$
DELIMITER ;

CALL ff_add_customer_user_unique_if_safe();
DROP PROCEDURE ff_add_customer_user_unique_if_safe;
