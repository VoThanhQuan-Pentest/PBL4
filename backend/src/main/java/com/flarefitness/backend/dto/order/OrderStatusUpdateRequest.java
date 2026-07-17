package com.flarefitness.backend.dto.order;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Size;

public record OrderStatusUpdateRequest(
        String status,
        @JsonAlias({"paymentStatus", "payment_status"}) String paymentStatus,
        @JsonAlias({"supportRequest", "support_request"}) String supportRequest,
        @JsonAlias({"supportStatus", "support_status"}) String supportStatus,
        @JsonAlias({"supportNote", "support_note"}) @Size(max = 1000) String supportNote,
        @JsonAlias({"requestType", "request_type"}) String requestType,
        @JsonAlias({"paymentConfirmedBy", "payment_confirmed_by"}) String paymentConfirmedBy,
        @JsonAlias({"paidAt", "paid_at"}) String paidAt
) {
}
