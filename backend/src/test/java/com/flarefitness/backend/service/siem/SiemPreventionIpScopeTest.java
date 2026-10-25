package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.exception.BadRequestException;
import org.junit.jupiter.api.Test;

class SiemPreventionIpScopeTest {
    @Test
    void acceptsOnlyNumericPublicAddressesForExternalLookupAndGlobalBlocks() {
        assertThat(SiemPreventionService.canonicalPublicIp("8.8.8.8")).isEqualTo("8.8.8.8");
        assertThat(SiemPreventionService.canonicalPublicIp("2001:4860:4860::8888"))
                .contains(":");
        for (String value : new String[] {
                "localhost", "127.0.0.1", "10.1.2.3", "192.0.2.8", "198.51.100.9",
                "203.0.113.10", "169.254.169.254", "100.64.1.1", "2001:db8::1",
                "::1", "ff02::1", "08.8.8.8", "8.8.8.8.evil.example"
        }) {
            assertThatThrownBy(() -> SiemPreventionService.canonicalPublicIp(value))
                    .as("IP %s should be excluded", value)
                    .isInstanceOf(BadRequestException.class);
        }
    }
}
