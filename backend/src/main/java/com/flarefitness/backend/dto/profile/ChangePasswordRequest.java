package com.flarefitness.backend.dto.profile;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "Mật khẩu hiện tại là bắt buộc.")
        @Size(max = 128, message = "Mật khẩu hiện tại không được vượt quá 128 ký tự.")
        String currentPassword,
        @NotBlank(message = "Mật khẩu mới là bắt buộc.")
        @Size(min = 12, max = 128, message = "Mật khẩu mới phải có từ 12 đến 128 ký tự.")
        String newPassword,
        @NotBlank(message = "Xác nhận mật khẩu là bắt buộc.")
        @Size(max = 128, message = "Xác nhận mật khẩu không được vượt quá 128 ký tự.")
        String confirmPassword
) {
}
