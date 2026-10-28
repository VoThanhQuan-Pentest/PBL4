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

    @Test
    void specialPurposeIpv4SpaceIsExcludedAcrossItsBoundaries() {
        rejected("0.1.2.3", "192.0.0.0", "192.0.0.1", "192.0.0.8", "192.0.0.11",
                "192.0.0.170", "192.0.0.171", "192.0.0.255", "192.88.99.0", "192.88.99.2",
                "192.88.99.255", "198.18.0.0", "198.19.255.255", "224.0.0.1", "239.255.255.255",
                "240.0.0.1", "255.255.255.255");
        accepted("192.0.0.9", "192.0.0.10", "192.0.1.0", "192.88.98.255", "192.88.100.0",
                "198.17.255.255", "198.20.0.0", "192.31.196.1", "192.52.193.1", "192.175.48.1");
    }

    @Test
    void specialPurposeIpv6AndUnknownTransitionRangesAreExcluded() {
        rejected("::", "::2", "64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
                "100::", "100::ffff:ffff:ffff:ffff", "100:0:0:1::1",
                "2001::1", "2001:1::", "2001:1::4", "2001:2::", "2001:2:0:ffff:ffff:ffff:ffff:ffff",
                "2001:10::1", "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
                "2001:db8::1", "2002:808:808::1", "3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
                "2000::1", "2001:1000::1", "2003:4000::1", "2420::1", "2612::1", "2622::1",
                "2640::1", "2810::1", "2a20::1", "2c10::1", "2d00::1", "3ffe::1", "3ffe:ffff::1",
                "3fff:1000::1", "4000::1", "5f00::1", "fc00::1", "fdff::1", "fe80::1");
    }

    @Test
    void globallyReachableMoreSpecificIpv6AllocationsOverrideTheirParent() {
        accepted("2001:1::1", "2001:1::2", "2001:1::3", "2001:3::", "2001:3:ffff:ffff:ffff:ffff:ffff:ffff",
                "2001:4:112::1", "2001:20::1", "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:30::1",
                "2001:3f:ffff:ffff:ffff:ffff:ffff:ffff", "2001:200::1", "2001:4860:4860::8888",
                "64:ff9b::808:808", "2620:4f:8000::1", "240f:ffff::1", "241f:ffff::1",
                "2606:4700:4700::1111", "263f:ffff::1", "2a02::1", "2a1f:ffff::1", "2c0f:ffff::1");
        rejected("2001:4:111:ffff:ffff:ffff:ffff:ffff", "2001:4:113::1", "2001:40::1");
    }

    @Test
    void equivalentNumericRepresentationsCannotBypassTheAddressPolicy() {
        rejected("::ffff:192.0.0.1", "::ffff:c000:1", "::ffff:10.1.2.3", "::ffff:127.0.0.1",
                "2001:0002:0000:0000:0000:0000:0000:0001", "3FFF:0000::1",
                "127.1", "2130706433", "0x7f.0.0.1", "1.2.3.256", "192.0.0.9/32", "[2001:1::1]",
                "fe80::1%eth0", "8.8.8.8@evil.example", "https://8.8.8.8/");
        assertThat(SiemPreventionService.canonicalPublicIp("::ffff:8.8.8.8")).isEqualTo("8.8.8.8");
        assertThat(SiemPreventionService.canonicalPublicIp(" 192.0.0.9 ")).isEqualTo("192.0.0.9");
    }

    private static void rejected(String... addresses) {
        for (String address : addresses) {
            assertThatThrownBy(() -> SiemPreventionService.canonicalPublicIp(address))
                    .as("Address %s must be ineligible", address).isInstanceOf(BadRequestException.class);
        }
    }

    private static void accepted(String... addresses) {
        for (String address : addresses) {
            assertThat(SiemPreventionService.canonicalPublicIp(address)).as("Address %s must remain eligible", address)
                    .isNotBlank();
        }
    }
}
