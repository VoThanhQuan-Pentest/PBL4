-- Legacy contacts deliberately remain unverified; do not invent provenance.
ALTER TABLE tbl_nguoi_dung ADD COLUMN email_verified_at DATETIME(6) NULL;

CREATE TABLE sensitive_action_confirmations (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    session_pseudonym VARCHAR(64) NOT NULL,
    auth_version BIGINT NOT NULL,
    contact_email VARCHAR(150) NOT NULL,
    contact_verified_at DATETIME(6) NOT NULL,
    operation VARCHAR(24) NOT NULL,
    profile_name VARCHAR(150) NULL,
    target_email VARCHAR(150) NULL,
    phone VARCHAR(32) NULL,
    password_hash VARCHAR(255) NULL,
    state VARCHAR(16) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    completed_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    INDEX idx_action_confirmation_user_expiry (user_id, expires_at),
    INDEX idx_action_confirmation_expiry (expires_at)
);
