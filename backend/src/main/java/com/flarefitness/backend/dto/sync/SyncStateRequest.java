package com.flarefitness.backend.dto.sync;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SyncStateRequest(
        @NotBlank @Size(max = 100_000, message = "Payload vuot qua gioi han cho phep.") String payload
) {
}
