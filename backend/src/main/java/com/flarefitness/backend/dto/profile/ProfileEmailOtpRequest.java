package com.flarefitness.backend.dto.profile;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ProfileEmailOtpRequest(
        @NotBlank(message = "Email la bat buoc.")
        @Email(message = "Email khong hop le.")
        @Size(max = 150, message = "Email khong duoc vuot qua 150 ky tu.")
        String email
) {
}
