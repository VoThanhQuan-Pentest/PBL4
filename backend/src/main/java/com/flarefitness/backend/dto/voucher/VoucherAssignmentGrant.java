package com.flarefitness.backend.dto.voucher;

import java.time.LocalDateTime;

public record VoucherAssignmentGrant(
        String code,
        int quantity,
        int used,
        LocalDateTime assignedAt
) {
}
