package com.flarefitness.backend.security;

import com.flarefitness.backend.exception.BadRequestException;
import org.springframework.stereotype.Component;

/**
 * Applies the password policy at the service boundary as well as through DTO
 * validation.  Service-level validation prevents callers that do not go
 * through an HTTP controller from bypassing the policy.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    public void validateNewPassword(String password) {
        if (password == null || password.isBlank()
                || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            throw new BadRequestException(
                    "Mat khau phai co tu %d den %d ky tu.".formatted(MIN_LENGTH, MAX_LENGTH));
        }
    }
}
