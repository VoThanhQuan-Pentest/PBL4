package com.flarefitness.backend.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Operator-owned sanitized/simulated fixtures, not real authentication or quality proof. */
class UebaSessionEndpointExportTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-08-01T00:00:00Z");

    @Test void realProducerPreservesSchema3PrefixAndAggregatesOnlySessionEndpointSignals() {
        var input = frame(false);
        var legacy = input.deepCopy(); legacy.put("telemetry_contract_version", 2);
        for (var event : legacy.path("events")) {
            ((ObjectNode) event).remove(List.of("endpoint_category", "session_pseudonym", "session_issued_at"));
        }
        var first = UebaFeatureExport.transform(input, new UebaFeatureExport.History(), 4);
        var previous = UebaFeatureExport.transform(legacy, new UebaFeatureExport.History(), 3);
        @SuppressWarnings("unchecked") List<Double> values = (List<Double>) first.get("features");
        assertThat(values).hasSize(37); assertThat(values.subList(0, 25)).isEqualTo(previous.get("features"));
        assertThat(values.subList(25, 37)).containsExactly(2.0,2.0,0.0,0.0,0.0,1.0,2.0,1.0,121.0,1.0,0.0,0.0);
        assertThat(first).containsEntry("data_provenance", "DEMO_ONLY");
        assertThat(first).containsEntry("telemetry_provenance", "OPERATOR_SANITIZED_OR_SIMULATED_CONTROLLED_TELEMETRY");
        assertThat(first).doesNotContainKeys("session_pseudonym", "session_issued_at", "endpoint_category", "token");
        var labelled = UebaFeatureExport.transform(frame(true), new UebaFeatureExport.History(), 4);
        assertThat(labelled.get("features")).isEqualTo(first.get("features"));
    }

    @Test void inventedVerificationFlagsRawTokensFutureIssuanceAndWrongContractsAreRefused() {
        for (String field : List.of("session_verified", "token", "jti", "raw_body")) {
            var input = frame(false); ((ObjectNode) input.path("events").get(0)).put(field, "not-allowed");
            assertThatThrownBy(() -> UebaFeatureExport.transform(input, new UebaFeatureExport.History(), 4))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        var future = frame(false); ((ObjectNode) future.path("events").get(0)).put("session_issued_at", START.plusSeconds(10).toString());
        assertThatThrownBy(() -> UebaFeatureExport.transform(future, new UebaFeatureExport.History(), 4)).isInstanceOf(IllegalArgumentException.class);
        var missing = frame(false); ((ObjectNode) missing.path("events").get(0)).remove("session_issued_at");
        assertThatThrownBy(() -> UebaFeatureExport.transform(missing, new UebaFeatureExport.History(), 4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> UebaFeatureExport.transform(frame(false), new UebaFeatureExport.History(), 3)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void sanitizedServerVocabularyPreservesAll37ValuesButCannotMixRawFields() {
        var raw = frame(false); var sanitized = raw.deepCopy();
        for (var event : sanitized.path("events")) {
            var value = (ObjectNode) event; value.remove(List.of("request_path", "user_agent"));
            value.put("route_group", "products"); value.put("user_agent_family", "OTHER");
        }
        assertThat(UebaFeatureExport.transform(sanitized, new UebaFeatureExport.History(), 4).get("features"))
                .isEqualTo(UebaFeatureExport.transform(raw, new UebaFeatureExport.History(), 4).get("features"));
        ((ObjectNode) sanitized.path("events").get(0)).put("request_path", "/api/products");
        assertThatThrownBy(() -> UebaFeatureExport.transform(sanitized, new UebaFeatureExport.History(), 4)).isInstanceOf(IllegalArgumentException.class);
        ((ObjectNode) sanitized.path("events").get(0)).remove("request_path");
        ((ObjectNode) sanitized.path("events").get(0)).put("route_group", "invented_group_42");
        assertThatThrownBy(() -> UebaFeatureExport.transform(sanitized, new UebaFeatureExport.History(), 4)).isInstanceOf(IllegalArgumentException.class);
    }

    private ObjectNode frame(boolean labelled) {
        var value = JSON.createObjectNode(); value.put("frame_id", "session-export-owned-frame");
        value.put("account_id", "session-export-owned-account"); value.put("day", 1); value.put("cohort", "COLD");
        value.put("window_start", START.toString()); value.put("telemetry_contract_version", 3);
        value.put("demo_label", labelled ? "ABNORMAL" : "NORMAL"); value.put("family", labelled ? "request_burst" : "normal");
        var events = value.putArray("events");
        for (int index = 0; index < 2; index++) {
            var event = events.addObject(); event.put("event_timestamp", START.plusSeconds(index + 1).toString());
            event.put("event_type", "HTTP_REQUEST"); event.put("action", "API_REQUEST"); event.put("outcome", "SUCCESS");
            event.put("http_status", 200); event.put("request_path", index == 0 ? "/api/products" : "/api/products/owned");
            event.put("http_method", "GET"); event.put("source_ip", "198.51.100.1"); event.put("user_agent", "owned-lab/1.0");
            event.put("endpoint_category", index == 0 ? "PRODUCT_LIST" : "PRODUCT_DETAIL");
            event.put("session_pseudonym", "a".repeat(64)); event.put("session_issued_at", START.minusSeconds(120).toString());
        }
        return value;
    }
}
