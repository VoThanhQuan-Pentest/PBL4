package com.flarefitness.backend.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class UebaFeatureExportTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant START = Instant.parse("2026-08-01T00:00:00Z");

    @Test
    void maturePersonalFeaturesUseTheSameBackendCountsAndDoNotReadGroundTruth() {
        var first = new UebaFeatureExport.History();
        var second = new UebaFeatureExport.History();
        for (int index = 0; index < 40; index++) {
            ObjectNode normal = frame(index, false);
            ObjectNode differentlyLabelled = frame(index, true);
            var a = UebaFeatureExport.transform(normal, first);
            var b = UebaFeatureExport.transform(differentlyLabelled, second);
            assertThat(a.get("features")).isEqualTo(b.get("features"));
            assertThat(a.get("baseline_established")).isEqualTo(index >= 30);
            assertThat(a.get("data_provenance")).isEqualTo("DEMO_ONLY");
        }
    }

    @Test
    void contextualExportPreservesOldPrefixAndIgnoresGroundTruthAndIdentity() {
        var first = new UebaFeatureExport.History(); var second = new UebaFeatureExport.History();
        for (int index = 0; index < 40; index++) {
            var normal = frame(index, false); var labelled = frame(index, true);
            var a = UebaFeatureExport.transform(normal, first, 3); var b = UebaFeatureExport.transform(labelled, second, 3);
            assertThat(a.get("features")).isEqualTo(b.get("features"));
            assertThat(a.get("feature_schema_version")).isEqualTo(3);
            @SuppressWarnings("unchecked") var values = (java.util.List<Double>) a.get("features");
            assertThat(values).hasSize(25);
            assertThat(values.get(15)).isEqualTo(1.0); assertThat(values.get(16)).isZero();
            var legacy = UebaFeatureExport.transform(frame(index, false), new UebaFeatureExport.History());
            if (index == 0) assertThat(values.subList(0, 15)).isEqualTo(legacy.get("features"));
        }
    }

    @Test
    void cannotAcceptFeatureVectorsOrRawBodiesAsEventEvidence() {
        ObjectNode vector = frame(0, false);
        vector.putArray("features").add(999);
        assertThatThrownBy(() -> UebaFeatureExport.transform(vector, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
        ObjectNode body = frame(0, false);
        ((ObjectNode) body.path("events").get(0)).put("raw_body", "not-allowed");
        assertThatThrownBy(() -> UebaFeatureExport.transform(body, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesDuplicateOrFutureEventsInsteadOfLeakingTemporalHistory() {
        var history = new UebaFeatureExport.History();
        UebaFeatureExport.transform(frame(0, false), history);
        assertThatThrownBy(() -> UebaFeatureExport.transform(frame(0, false), history))
                .isInstanceOf(IllegalArgumentException.class);
        ObjectNode future = frame(1, false);
        ((ObjectNode) future.path("events").get(0)).put("event_timestamp", START.plusSeconds(4000).toString());
        assertThatThrownBy(() -> UebaFeatureExport.transform(future, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static ObjectNode frame(int index, boolean abnormalLabel) {
        ObjectNode node = JSON.createObjectNode();
        Instant at = START.plusSeconds(index * 900L);
        node.put("frame_id", "export-fixture-" + index);
        node.put("account_id", "export-owned-account");
        node.put("day", 1);
        node.put("cohort", "DEVELOPMENT");
        node.put("window_start", at.toString());
        node.put("demo_label", abnormalLabel ? "ABNORMAL" : "NORMAL");
        node.put("family", abnormalLabel ? "request_burst" : "normal");
        ObjectNode event = node.putArray("events").addObject();
        event.put("event_timestamp", at.plusSeconds(1).toString());
        event.put("event_type", "HTTP_REQUEST");
        event.put("action", "API_REQUEST");
        event.put("outcome", "SUCCESS");
        event.put("http_status", 200);
        event.put("route_group", "products");
        event.put("source_ip", "198.51.100.1");
        event.put("user_agent_family", "CHROMIUM");
        return node;
    }

    @Test
    void strictRawEventsUseActualRouteAndAgentVocabularyWithoutPersistingRawValues() {
        ObjectNode input = frame(0, true);
        input.put("telemetry_contract_version", 2);
        ObjectNode request = (ObjectNode) input.path("events").get(0);
        request.remove("route_group"); request.remove("user_agent_family");
        request.put("request_path", "/api/owned-missing-endpoint");
        request.put("user_agent", "owned-lab-scanner/1.0"); request.put("http_method", "GET");
        var result = UebaFeatureExport.transform(input, new UebaFeatureExport.History());
        assertThat(result.get("telemetry_contract_version")).isEqualTo(2);
        assertThat(result).doesNotContainKey("request_path").doesNotContainKey("user_agent");
        @SuppressWarnings("unchecked") var values = (java.util.List<Double>) result.get("features");
        assertThat(values.get(6)).isEqualTo(1.0); // one other_api group, not an invented group per endpoint
        request.put("route_group", "group_42");
        assertThatThrownBy(() -> UebaFeatureExport.transform(input, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rawV2TemporalGapsMaySpanLongerMetadataWithoutRelaxingLegacyOrPayloadBounds() {
        ObjectNode legacy = frame(0, false); legacy.put("day", 110);
        assertThatThrownBy(() -> UebaFeatureExport.transform(legacy, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
        ObjectNode input = frame(0, false); input.put("day", 110); input.put("telemetry_contract_version", 2);
        ObjectNode request = (ObjectNode) input.path("events").get(0);
        request.remove("route_group"); request.remove("user_agent_family");
        request.put("request_path", "/api/products"); request.put("user_agent", "Firefox/133.0"); request.put("http_method", "GET");
        assertThat(UebaFeatureExport.transform(input, new UebaFeatureExport.History()).get("day")).isEqualTo(110);
        input.put("day", 111);
        assertThatThrownBy(() -> UebaFeatureExport.transform(input, new UebaFeatureExport.History()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
