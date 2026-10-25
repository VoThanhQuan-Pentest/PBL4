ALTER TABLE sensitive_action_confirmations
    ADD COLUMN policy_id VARCHAR(96) NOT NULL DEFAULT 'legacy-unbound' AFTER operation;

-- Pending legacy records did not persist an authorization-policy binding.
-- Do not retroactively declare them verified under the newly bound policy.
UPDATE sensitive_action_confirmations
SET state = 'EXPIRED', password_hash = NULL, profile_name = NULL,
    target_email = NULL, phone = NULL
WHERE state = 'PENDING';
