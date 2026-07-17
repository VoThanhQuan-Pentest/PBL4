package com.flarefitness.backend.security;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

@Component
public class IpAddressResolver {

    private final List<CidrBlock> trustedProxyCidrs;

    public IpAddressResolver(@Value("${app.security.trusted-proxy-cidrs:}") String trustedProxyCidrs) {
        this.trustedProxyCidrs = Arrays.stream(String.valueOf(trustedProxyCidrs).split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(CidrBlock::parse)
                .toList();
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddress = normalizeIp(request.getRemoteAddr());
        if (!isTrustedProxy(remoteAddress)) {
            return remoteAddress;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddress;
        }

        String[] chain = forwardedFor.split(",");
        for (int index = chain.length - 1; index >= 0; index--) {
            String candidate = normalizeIp(chain[index]);
            if (!candidate.isBlank() && !isTrustedProxy(candidate)) {
                return candidate;
            }
        }
        return remoteAddress;
    }

    private boolean isTrustedProxy(String ipAddress) {
        if (ipAddress.isBlank() || trustedProxyCidrs.isEmpty()) {
            return false;
        }
        return trustedProxyCidrs.stream().anyMatch(block -> block.contains(ipAddress));
    }

    private static String normalizeIp(String value) {
        String ipAddress = String.valueOf(value == null ? "" : value).trim();
        return ipAddress.startsWith("::ffff:") ? ipAddress.substring(7) : ipAddress;
    }

    private record CidrBlock(long network, long mask) {
        private static CidrBlock parse(String value) {
            String[] parts = value.split("/", 2);
            int prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : 32;
            if (prefix < 0 || prefix > 32) {
                throw new IllegalArgumentException("Invalid trusted proxy CIDR: " + value);
            }
            long mask = prefix == 0 ? 0 : (-1L << (32 - prefix)) & 0xffffffffL;
            long network = toIpv4Long(parts[0]) & mask;
            return new CidrBlock(network, mask);
        }

        private boolean contains(String ipAddress) {
            try {
                return (toIpv4Long(ipAddress) & mask) == network;
            } catch (IllegalArgumentException exception) {
                return false;
            }
        }

        private static long toIpv4Long(String ipAddress) {
            try {
                byte[] bytes = InetAddress.getByName(ipAddress).getAddress();
                if (bytes.length != 4) {
                    throw new IllegalArgumentException("Only IPv4 CIDR entries are supported.");
                }
                long result = 0;
                for (byte item : bytes) {
                    result = (result << 8) | (item & 0xffL);
                }
                return result;
            } catch (UnknownHostException exception) {
                throw new IllegalArgumentException("Invalid IP address: " + ipAddress, exception);
            }
        }
    }
}
