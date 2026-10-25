package com.flarefitness.backend.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.service.siem.EndpointCategory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/** Offline source-file probe against immutable production class bytes. No HTTP/DB/network. */
public final class Schema4EndpointVocabularyProbe {
    private Schema4EndpointVocabularyProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("No caller-selected routes or executable input allowed");
        List<String> routes = List.of(
                "GET /api/products", "GET /api/products/query", "GET /api/products/{id}",
                "GET /api/profile", "PUT /api/profile", "POST /api/profile/email/otp", "PUT /api/profile/password",
                "GET /api/orders/me", "GET /api/orders/me/page", "POST /api/orders",
                "POST /api/orders/{orderId}/cancel-request", "POST /api/orders/{orderId}/return-request",
                "GET /api/support/me", "GET /api/support/me/messages", "POST /api/support/me/messages",
                "GET /api/reviews/products/{productId}", "GET /api/reviews/products/{productId}/page", "POST /api/reviews",
                "GET /api/promo-hunt/campaigns", "POST /api/promo-hunt/campaigns/{campaignId}/claim",
                "GET /api/sync/me/{key}", "PUT /api/sync/me/{key}", "GET /api/sync/app/{key}", "PUT /api/sync/app/{key}",
                "GET /api/admin/dashboard", "GET /api/owned-lab/controlled-faults");
        var categories = new ArrayList<String>();
        for (var category : EndpointCategory.values()) categories.add(category.name());
        var mappings = new ArrayList<Object>();
        for (String route : routes) {
            String[] parts = route.split(" ", 2);
            mappings.add(new LinkedHashMap<>(java.util.Map.of("method", parts[0], "handler_pattern", parts[1],
                    "endpoint_category", EndpointCategory.fromHandlerPattern(parts[0], parts[1]).name())));
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("scope", "ACTUAL_IMMUTABLE_ENDPOINT_CLASSIFIER_OFFLINE_ONLY");
        result.put("telemetry_contract_version", 3);
        result.put("feature_schema_version", 4);
        result.put("endpoint_categories", categories);
        result.put("handler_mappings", mappings);
        result.put("http_handler_resolution_proven", false);
        result.put("authenticated_session_proven", false);
        result.put("quality_gate", "NOT_APPLICABLE");
        System.out.println(new ObjectMapper().writeValueAsString(result));
    }
}
