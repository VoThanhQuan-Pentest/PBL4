package com.flarefitness.backend.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordRequest(
        @NotBlank(message = "Email la bat buoc.")
        @Email(message = "Email khong dung dinh dang.")
        @Size(max = 150, message = "Email khong duoc vuot qua 150 ky tu.")
        String email,
        @NotBlank(message = "Phien dat lai mat khau la bat buoc.")
        @Size(max = 100, message = "Phien dat lai mat khau khong hop le.")
        String resetToken,
        @NotBlank(message = "Mat khau moi la bat buoc.")
        @Size(min = 12, max = 128, message = "Mat khau moi phai co tu 12 den 128 ky tu.")
        String newPassword,
        @NotBlank(message = "Xac nhan mat khau la bat buoc.")
        @Size(max = 128, message = "Xac nhan mat khau khong duoc vuot qua 128 ky tu.")
        String confirmPassword
) {
}
