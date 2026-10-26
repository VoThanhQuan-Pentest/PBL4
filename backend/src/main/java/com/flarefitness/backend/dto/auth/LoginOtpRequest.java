package com.flarefitness.backend.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record LoginOtpRequest(
        @NotBlank @Pattern(regexp = "[0-9a-fA-F-]{36}") String challengeId,
        @NotBlank @Pattern(regexp = "[0-9]{6}") String otpCode
) { }
