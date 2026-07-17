package com.flarefitness.backend.dto.voucher;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * JSON shape retained for legacy clients at /api/sync/me/voucher-assignments.
 */
public record VoucherAssignmentSyncPayload(
        String accountKey,
        String accountLabel,
        List<String> codes,
        Map<String, VoucherAssignmentGrant> grants,
        LocalDateTime updatedAt
) {
}
