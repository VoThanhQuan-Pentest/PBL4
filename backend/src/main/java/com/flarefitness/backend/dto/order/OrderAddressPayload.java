package com.flarefitness.backend.dto.order;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record OrderAddressPayload(
        String id,
        @NotBlank @Size(max = 150) String recipient,
        @NotBlank @Pattern(regexp = "^(0|\\+84)(3|5|7|8|9)\\d{8}$") String phone,
        @JsonAlias({"line", "addressLine", "address_line"})
        @NotBlank @Size(max = 255) String detail,
        @Size(max = 100) String street,
        @NotBlank @Size(max = 100) String ward,
        @Size(max = 100) String district,
        @JsonAlias({"city", "provinceName", "province_name"})
        @NotBlank @Size(max = 100) String province,
        @JsonAlias({"fullText", "full_text", "addressText", "address_text"})
        @Size(max = 500) String text
) {
}
