package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class EndpointCategoryTest {
    @Test
    void mapsActualCanonicalCustomerWorkflowsNarrowly() {
        Map<String, EndpointCategory> cases = Map.ofEntries(
                Map.entry("GET /api/products", EndpointCategory.PRODUCT_LIST),
                Map.entry("GET /api/products/query", EndpointCategory.PRODUCT_LIST),
                Map.entry("GET /api/products/{id}", EndpointCategory.PRODUCT_DETAIL),
                Map.entry("GET /api/profile", EndpointCategory.PROFILE_READ),
                Map.entry("PUT /api/profile", EndpointCategory.PROFILE_UPDATE),
                Map.entry("POST /api/profile/email/otp", EndpointCategory.PROFILE_EMAIL_OTP),
                Map.entry("PUT /api/profile/password", EndpointCategory.PROFILE_PASSWORD),
                Map.entry("GET /api/orders/me/page", EndpointCategory.ORDERS_READ),
                Map.entry("POST /api/orders", EndpointCategory.ORDER_CREATE),
                Map.entry("POST /api/orders/{orderId}/cancel-request", EndpointCategory.ORDER_CANCEL),
                Map.entry("POST /api/orders/{orderId}/return-request", EndpointCategory.ORDER_RETURN),
                Map.entry("GET /api/support/me/messages", EndpointCategory.SUPPORT_READ),
                Map.entry("POST /api/support/me/messages", EndpointCategory.SUPPORT_SEND),
                Map.entry("GET /api/reviews/products/{productId}/page", EndpointCategory.REVIEW_READ),
                Map.entry("POST /api/reviews", EndpointCategory.REVIEW_CREATE),
                Map.entry("GET /api/promo-hunt/campaigns", EndpointCategory.PROMO_LIST),
                Map.entry("POST /api/promo-hunt/campaigns/{campaignId}/claim", EndpointCategory.PROMO_CLAIM),
                Map.entry("GET /api/sync/app/{key}", EndpointCategory.SYNC_READ),
                Map.entry("PUT /api/sync/me/{key}", EndpointCategory.SYNC_WRITE),
                Map.entry("PUT /api/sync/app/{key}", EndpointCategory.PRIVILEGED));
        cases.forEach((route, category) -> {
            String[] parts = route.split(" ", 2);
            assertThat(EndpointCategory.fromHandlerPattern(parts[0], parts[1])).as(route).isEqualTo(category);
        });
        assertThat(EndpointCategory.fromHandlerPattern("GET", "/api/products/query/unknown")).isEqualTo(EndpointCategory.OTHER_MATCHED);
        assertThat(EndpointCategory.fromHandlerPattern("GET", "/api/products/user-secret")).isEqualTo(EndpointCategory.OTHER_MATCHED);
        assertThat(EndpointCategory.fromHandlerPattern(null, null)).isEqualTo(EndpointCategory.UNRESOLVED);
    }

    @Test
    void storedCategoriesAreExactAllowlistAndUnresolvedIsNotMatched() {
        for (EndpointCategory category : EndpointCategory.values()) {
            assertThat(EndpointCategory.fromStored(category.name())).contains(category);
        }
        assertThat(EndpointCategory.fromStored(null)).isEmpty();
        assertThat(EndpointCategory.fromStored("product_list")).isEmpty();
        assertThat(EndpointCategory.fromStored("/api/products/private")).isEmpty();
        assertThat(EndpointCategory.UNMATCHED.isMatched()).isFalse();
        assertThat(EndpointCategory.UNRESOLVED.isMatched()).isFalse();
        assertThat(EndpointCategory.OTHER_MATCHED.isMatched()).isTrue();
    }
}
