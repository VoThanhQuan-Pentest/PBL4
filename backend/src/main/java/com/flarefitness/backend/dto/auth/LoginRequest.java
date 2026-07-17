package com.flarefitness.backend.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Tên đăng nhập là bắt buộc.")
        @Size(max = 100, message = "Tên đăng nhập không được vượt quá 100 ký tự.")
        String username,
        @NotBlank(message = "Mật khẩu là bắt buộc.")
        @Size(max = 128, message = "Mật khẩu không được vượt quá 128 ký tự.")
        String password
) {
}
