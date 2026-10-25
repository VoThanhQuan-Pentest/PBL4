package com.flarefitness.backend.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;

public record ApiErrorResponse(
        OffsetDateTime timestamp,
        int status,
        String error,
        String message,
        String code,
        @JsonProperty("traceId") String traceId,
        @JsonProperty("decision_id") @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) String decisionId,
        @JsonProperty("retry_after_seconds") @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) Integer retryAfterSeconds
) {
    public ApiErrorResponse(OffsetDateTime timestamp, int status, String error, String message, String code, String traceId) {
        this(timestamp, status, error, message, code, traceId, null, null);
    }
}
