package com.flarefitness.backend.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record OtpRequest(
        @Size(max = 100, message = "Ten dang nhap khong duoc vuot qua 100 ky tu.")
        String username,
        @NotBlank(message = "Email la bat buoc.")
        @Email(message = "Email khong dung dinh dang.")
        @Size(max = 150, message = "Email khong duoc vuot qua 150 ky tu.")
        String email,
        @Size(max = 30, message = "So dien thoai khong duoc vuot qua 30 ky tu.")
        String sdt
) {
}
