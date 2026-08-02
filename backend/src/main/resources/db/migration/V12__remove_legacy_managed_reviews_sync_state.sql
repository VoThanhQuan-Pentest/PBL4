DELETE FROM tbl_sync_state
WHERE scope = 'APP'
  AND owner_id IS NULL
  AND state_key = 'managed-reviews';
