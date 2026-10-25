package com.flarefitness.backend.service.siem;

import java.util.Optional;

/** Bounded workflow vocabulary; classification accepts only a Spring-resolved handler template. */
public enum EndpointCategory {
    PRODUCT_LIST, PRODUCT_DETAIL,
    PROFILE_READ, PROFILE_UPDATE, PROFILE_EMAIL_OTP, PROFILE_PASSWORD,
    ORDERS_READ, ORDER_CREATE, ORDER_CANCEL, ORDER_RETURN,
    SUPPORT_READ, SUPPORT_SEND, REVIEW_READ, REVIEW_CREATE,
    PROMO_LIST, PROMO_CLAIM, SYNC_READ, SYNC_WRITE,
    PRIVILEGED, OTHER_MATCHED, UNMATCHED, UNRESOLVED;

    public boolean isMatched() { return this != UNMATCHED && this != UNRESOLVED; }

    public static Optional<EndpointCategory> fromStored(String value) {
        if (value == null) return Optional.empty();
        try { return Optional.of(valueOf(value)); }
        catch (IllegalArgumentException invalid) { return Optional.empty(); }
    }

    /** Never call this with a raw URI, a path variable, or a forwarded/request header. */
    public static EndpointCategory fromHandlerPattern(String method, String pattern) {
        if (method == null || pattern == null) return UNRESOLVED;
        if (pattern.startsWith("/api/admin/") || pattern.startsWith("/api/siem/")
                || pattern.startsWith("/api/support/threads")) return PRIVILEGED;
        return switch (method + " " + pattern) {
            case "GET /api/products", "GET /api/products/query" -> PRODUCT_LIST;
            case "GET /api/products/{id}" -> PRODUCT_DETAIL;
            case "GET /api/profile" -> PROFILE_READ;
            case "PUT /api/profile" -> PROFILE_UPDATE;
            case "POST /api/profile/email/otp" -> PROFILE_EMAIL_OTP;
            case "PUT /api/profile/password" -> PROFILE_PASSWORD;
            case "GET /api/orders/me", "GET /api/orders/me/page" -> ORDERS_READ;
            case "POST /api/orders" -> ORDER_CREATE;
            case "POST /api/orders/{orderId}/cancel-request" -> ORDER_CANCEL;
            case "POST /api/orders/{orderId}/return-request" -> ORDER_RETURN;
            case "GET /api/orders", "GET /api/orders/page", "PATCH /api/orders/{orderId}",
                    "GET /api/reviews", "GET /api/reviews/page", "PATCH /api/reviews/{id}",
                    "DELETE /api/reviews/{id}", "PUT /api/sync/app/{key}" -> PRIVILEGED;
            case "GET /api/support/me", "GET /api/support/me/messages" -> SUPPORT_READ;
            case "POST /api/support/me/messages" -> SUPPORT_SEND;
            case "GET /api/reviews/products/{productId}", "GET /api/reviews/products/{productId}/page" -> REVIEW_READ;
            case "POST /api/reviews" -> REVIEW_CREATE;
            case "GET /api/promo-hunt/campaigns" -> PROMO_LIST;
            case "POST /api/promo-hunt/campaigns/{campaignId}/claim" -> PROMO_CLAIM;
            case "GET /api/sync/me/{key}", "GET /api/sync/app/{key}" -> SYNC_READ;
            case "PUT /api/sync/me/{key}" -> SYNC_WRITE;
            default -> OTHER_MATCHED;
        };
    }
}
