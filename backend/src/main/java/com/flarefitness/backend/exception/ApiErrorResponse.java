package com.flarefitness.backend.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;

public record ApiErrorResponse(
        OffsetDateTime timestamp,
        int status,
        String error,
        String message,
        String code,
        @JsonProperty("traceId") String traceId
) {
}
