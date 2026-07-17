package com.flarefitness.backend.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordOtpVerifyRequest(
        @NotBlank(message = "Email la bat buoc.")
        @Email(message = "Email khong dung dinh dang.")
        @Size(max = 150, message = "Email khong duoc vuot qua 150 ky tu.")
        String email,
        @NotBlank(message = "Ma OTP la bat buoc.")
        @Size(min = 6, max = 6, message = "Ma OTP phai gom 6 chu so.")
        String otpCode
) {
}
