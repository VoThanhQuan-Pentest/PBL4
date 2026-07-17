package com.flarefitness.backend.dto.order;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import java.util.List;

public record OrderRequest(
        @Size(max = 64) String id,
        @Size(max = 64) String code,
        @JsonAlias("createdAt") String createdAt,
        BigDecimal subtotal,
        BigDecimal shipping,
        BigDecimal discount,
        BigDecimal total,
        @JsonAlias("voucherCode") String voucherCode,
        @JsonAlias("voucherLabel") String voucherLabel,
        @NotNull @Valid OrderAddressPayload address,
        @NotEmpty @Size(max = 50, message = "Don hang toi da 50 dong san pham.") List<@Valid OrderItemPayload> items
) {
}
