package com.flarefitness.backend.service.siem;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Numeric address classification, not a network reachability probe. */
final class PublicIpEligibility {
    // IANA IPv4/IPv6 Special-Purpose Address Registries, updated 2025-10-09,
    // reviewed 2026-10-28. False, N/A and retired entries are ineligible.
    // https://www.iana.org/assignments/iana-ipv4-special-registry/
    // https://www.iana.org/assignments/iana-ipv6-special-registry/
    // More-specific globally-reachable allocations override their parent.
    // IPv6 Global Unicast Address Assignments, updated 2025-10-10. Unlisted
    // space is reserved for future allocation, including the returned 6bone.
    // https://www.iana.org/assignments/ipv6-unicast-address-assignments/
    private static final Prefix[] ALLOCATED_V6 = {
            prefix("2001::/23", true), prefix("2001:200::/23", true), prefix("2001:400::/23", true),
            prefix("2001:600::/23", true), prefix("2001:800::/22", true), prefix("2001:c00::/23", true),
            prefix("2001:e00::/23", true), prefix("2001:1200::/23", true), prefix("2001:1400::/22", true),
            prefix("2001:1800::/23", true), prefix("2001:1a00::/23", true), prefix("2001:1c00::/22", true),
            prefix("2001:2000::/19", true), prefix("2001:4000::/23", true), prefix("2001:4200::/23", true),
            prefix("2001:4400::/23", true), prefix("2001:4600::/23", true), prefix("2001:4800::/23", true),
            prefix("2001:4a00::/23", true), prefix("2001:4c00::/23", true), prefix("2001:5000::/20", true),
            prefix("2001:8000::/19", true), prefix("2001:a000::/20", true), prefix("2001:b000::/20", true),
            prefix("2002::/16", true), prefix("2003::/18", true), prefix("2400::/12", true),
            prefix("2410::/12", true), prefix("2600::/12", true), prefix("2610::/23", true),
            prefix("2620::/23", true), prefix("2630::/12", true), prefix("2800::/12", true),
            prefix("2a00::/12", true), prefix("2a10::/12", true), prefix("2c00::/12", true)
    };

    private static final Prefix[] SPECIAL = {
            prefix("0.0.0.0/8", false),
            prefix("10.0.0.0/8", false),
            prefix("100.64.0.0/10", false),
            prefix("127.0.0.0/8", false),
            prefix("169.254.0.0/16", false),
            prefix("172.16.0.0/12", false),
            prefix("192.0.0.0/24", false),
            prefix("192.0.0.9/32", true),
            prefix("192.0.0.10/32", true),
            prefix("192.0.2.0/24", false),
            prefix("192.31.196.0/24", true),
            prefix("192.52.193.0/24", true),
            prefix("192.88.99.0/24", false),
            prefix("192.168.0.0/16", false),
            prefix("192.175.48.0/24", true),
            prefix("198.18.0.0/15", false),
            prefix("198.51.100.0/24", false),
            prefix("203.0.113.0/24", false),
            prefix("240.0.0.0/4", false),
            prefix("::/128", false),
            prefix("::1/128", false),
            prefix("64:ff9b::/96", true),
            prefix("64:ff9b:1::/48", false),
            prefix("100::/64", false),
            prefix("100:0:0:1::/64", false),
            prefix("2001::/23", false),
            prefix("2001::/32", false),
            prefix("2001:1::1/128", true),
            prefix("2001:1::2/128", true),
            prefix("2001:1::3/128", true),
            prefix("2001:2::/48", false),
            prefix("2001:3::/32", true),
            prefix("2001:4:112::/48", true),
            prefix("2001:10::/28", false),
            prefix("2001:20::/28", true),
            prefix("2001:30::/28", true),
            prefix("2001:db8::/32", false),
            prefix("2002::/16", false),
            prefix("2620:4f:8000::/48", true),
            prefix("3fff::/20", false),
            prefix("5f00::/16", false),
            prefix("fc00::/7", false),
            prefix("fe80::/10", false)
    };

    private PublicIpEligibility() { }

    static boolean isEligible(InetAddress ip) {
        // InetAddress normalizes IPv4-mapped IPv6 to IPv4; apply its IPv4 policy.
        byte[] address = ip.getAddress();
        boolean allowed = address.length == 4 && (address[0] & 0xff) < 224;
        if (address.length == 16) {
            for (Prefix allocation : ALLOCATED_V6) {
                if (allocation.matches(address)) {
                    allowed = true;
                    break;
                }
            }
        }
        int longest = -1;
        for (Prefix prefix : SPECIAL) {
            if (prefix.bits() > longest && prefix.matches(address)) {
                longest = prefix.bits();
                allowed = prefix.global();
            }
        }
        return allowed;
    }

    private static Prefix prefix(String cidr, boolean global) {
        String[] parts = cidr.split("/", -1);
        try {
            // Only fixed numeric source literals reach this constructor, never request text.
            byte[] network = InetAddress.getByName(parts[0]).getAddress();
            int bits = Integer.parseInt(parts[1]);
            if (bits < 0 || bits > network.length * 8) throw new IllegalArgumentException("Invalid prefix");
            return new Prefix(network, bits, global);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException("Invalid fixed IP policy prefix", exception);
        }
    }

    private record Prefix(byte[] network, int bits, boolean global) {
        boolean matches(byte[] address) {
            if (network.length != address.length) return false;
            int full = bits / 8;
            for (int index = 0; index < full; index++) {
                if (network[index] != address[index]) return false;
            }
            int remainder = bits % 8;
            if (remainder == 0) return true;
            int mask = (0xff << (8 - remainder)) & 0xff;
            return ((address[full] & 0xff) & mask) == ((network[full] & 0xff) & mask);
        }
    }
}
