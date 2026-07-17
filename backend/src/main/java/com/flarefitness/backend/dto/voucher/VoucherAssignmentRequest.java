package com.flarefitness.backend.dto.voucher;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record VoucherAssignmentRequest(
        @NotBlank @Size(max = 64) String userId,
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{2,64}") String voucherCode,
        @Min(1) @Max(1000) int quantity
) {
}
