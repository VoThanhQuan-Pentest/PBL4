package com.flarefitness.backend.dto.auth;

public record PasswordResetVerificationResponse(
        String resetToken
) {
}
