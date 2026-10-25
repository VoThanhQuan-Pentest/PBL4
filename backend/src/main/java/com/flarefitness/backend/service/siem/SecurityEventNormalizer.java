package com.flarefitness.backend.service.siem;

import java.util.Locale;
import java.util.Set;

/** Shared live/export telemetry vocabulary. Raw paths/agents are never persisted by this class. */
public final class SecurityEventNormalizer {
    public static final int CONTRACT_VERSION = 2;
    public static final Set<String> REQUEST_GROUPS = Set.of("admin", "profile", "orders", "support", "reviews",
            "promo_hunt", "sync", "products", "other_api");
    public static final Set<String> AGENT_FAMILIES = Set.of("EDGE", "FIREFOX", "CHROMIUM", "SAFARI", "OTHER");

    private SecurityEventNormalizer() { }

    public static String routeGroup(String path) {
        if (path == null || !path.startsWith("/api/")) return null;
        if (path.indexOf('?') >= 0 || path.indexOf('#') >= 0) throw new IllegalArgumentException("Request URI must exclude query/fragment.");
        if (path.startsWith("/api/analytics/") || path.startsWith("/api/siem/")
                || path.startsWith("/api/health") || path.startsWith("/api/auth/")) return null;
        if (path.startsWith("/api/admin/")) return "admin";
        if (path.startsWith("/api/profile")) return "profile";
        if (path.startsWith("/api/orders")) return "orders";
        if (path.startsWith("/api/support")) return "support";
        if (path.startsWith("/api/reviews")) return "reviews";
        if (path.startsWith("/api/promo-hunt")) return "promo_hunt";
        if (path.startsWith("/api/sync")) return "sync";
        if (path.startsWith("/api/products")) return "products";
        return "other_api";
    }

    public static String userAgentFamily(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String agent = raw.toLowerCase(Locale.ROOT);
        if (agent.contains("edg/")) return "EDGE";
        if (agent.contains("firefox/")) return "FIREFOX";
        if (agent.contains("chrome/") || agent.contains("chromium/")) return "CHROMIUM";
        if (agent.contains("safari/")) return "SAFARI";
        return "OTHER";
    }
}
