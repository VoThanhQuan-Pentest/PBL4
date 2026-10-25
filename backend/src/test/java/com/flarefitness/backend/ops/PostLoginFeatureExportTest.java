package com.flarefitness.backend.ops;

import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PostLoginFeatureExportTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test void typedRiskSnapshotHasExactlyTheOffline65ValuesAndIgnoresFutureOutcomes() throws Exception {
        var frame = frame();
        var attempt = observed(frame.path("attempt"));
        var context = new ArrayList<SiemSecurityEvent>(); frame.path("context").forEach(e -> context.add(observed(e)));
        var typed = PostLoginFeatureExport.fromObservedRisk(attempt, context, List.of());
        var transport = PostLoginFeatureExport.transformRisk(frame, new UebaFeatureExport.History());
        assertThat(typed.values()).hasSize(65);
        assertThat(typed.rollingFeatures()).isEqualTo(transport.get("rolling_features"));
        assertThat(typed.values().subList(0, 37)).isEqualTo(transport.get("baseline_features"));
        assertThat(typed.values().subList(37, 57)).isEqualTo(transport.get("postlogin_features"));
        context.add(observed(event("DOMAIN_ACTION", "PASSWORD_CHANGE", "SUCCESS", "2026-08-01T00:00:21Z")));
        assertThat(PostLoginFeatureExport.fromObservedRisk(attempt, context, List.of()).values()).isEqualTo(typed.values());
        assertThatThrownBy(() -> typed.values().set(0, 99.0)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test void rollingExportRetainsPriorWindowFailuresAndKeepsLegacyViewUnchanged() throws Exception {
        var frame = frame(); frame.withArray("context").removeAll();
        ((ObjectNode) frame.path("attempt")).put("event_timestamp", "2026-08-01T00:15:05Z");
        var failure = event("AUTH", "LOGIN", "FAILURE", "2026-08-01T00:14:30Z");
        failure.remove("actor_user_id"); failure.put("target_user_id", "owned-account");
        frame.withArray("context").add(failure);
        var legacy = PostLoginFeatureExport.transform(frame);
        var rolling = PostLoginFeatureExport.transformRisk(frame, new UebaFeatureExport.History());
        assertThat(rolling.get("baseline_features")).isEqualTo(legacy.get("baseline_features"));
        assertThat(rolling.get("postlogin_features")).isEqualTo(legacy.get("postlogin_features"));
        @SuppressWarnings("unchecked") var values = (List<Double>) rolling.get("rolling_features");
        assertThat(values).hasSize(8); assertThat(values.get(4)).isEqualTo(1);
        assertThat(legacy).doesNotContainKey("rolling_features");
    }

    @Test void typedServerSnapshotMatchesColdTransportAndIgnoresFutureOutcomeAndLabels() throws Exception {
        var frame = frame();
        var attempt = observed(frame.path("attempt"));
        var context = new ArrayList<SiemSecurityEvent>(); frame.path("context").forEach(e -> context.add(observed(e)));
        var typed = PostLoginFeatureExport.fromObserved(attempt, context, List.of());
        var transport = PostLoginFeatureExport.transform(frame);
        assertThat(typed.baselineFeatures()).hasSize(37).isEqualTo(transport.get("baseline_features"));
        assertThat(typed.postlogin().values()).isEqualTo(transport.get("postlogin_features"));
        assertThat(typed.baselineEstablished()).isFalse(); assertThat(typed.trustedWindowCount()).isZero();
        assertThat(typed.baselineFeatures().get(0)).isEqualTo(1); assertThat(typed.baselineFeatures().get(5)).isZero();
        attempt.setDemoLabel("ABNORMAL"); context.forEach(e -> e.setDemoLabel("ABNORMAL"));
        context.add(observed(event("DOMAIN_ACTION", "PASSWORD_CHANGE", "SUCCESS", "2026-08-01T00:00:21Z")));
        assertThat(PostLoginFeatureExport.fromObserved(attempt, context, List.of())).isEqualTo(typed);
    }

    @Test void typedServerSnapshotPreservesTheExistingReadyHistoryCalculation() throws Exception {
        var frame = frame(); var history = new UebaFeatureExport.History();
        LocalDateTime start = LocalDateTime.of(2026, 8, 1, 0, 0);
        for (int i = 30; i >= 1; i--) {
            LocalDateTime past = start.minusMinutes(15L * i);
            var prior = JSON.createObjectNode().put("frame_id", "ready-prior-frame-" + i).put("account_id", "owned-account")
                    .put("day", 1).put("cohort", "COLD").put("window_start", past.toInstant(ZoneOffset.UTC).toString())
                    .put("demo_label", "NORMAL").put("family", "normal").put("telemetry_contract_version", 3);
            var request = event("HTTP_REQUEST", "API_REQUEST", "SUCCESS", past.plusSeconds(1).toInstant(ZoneOffset.UTC).toString());
            request.remove(List.of("actor_user_id", "session_pseudonym", "session_issued_at", "telemetry_contract_version"));
            request.put("http_status", 200).put("http_method", "GET").put("route_group", "profile").put("endpoint_category", "PROFILE_READ");
            prior.putArray("events").add(request); frame.withArray("baseline_frames").add(prior);
            UebaFeatureExport.transform(prior, history, 4);
        }
        var context = new ArrayList<SiemSecurityEvent>(); frame.path("context").forEach(e -> context.add(observed(e)));
        var typed = PostLoginFeatureExport.fromObserved(observed(frame.path("attempt")), context, history.before("owned-account", start));
        assertThat(typed.baselineFeatures()).isEqualTo(PostLoginFeatureExport.transform(frame).get("baseline_features"));
        assertThat(typed.baselineEstablished()).isTrue(); assertThat(typed.trustedWindowCount()).isEqualTo(30);
    }

    @Test void typedServerSnapshotRejectsUnrelatedOrUnclosedHistoricalWindows() throws Exception {
        var attempt = observed(frame().path("attempt"));
        var window = new SiemAccountBehaviorWindow(); window.setAccountId("other-account");
        window.setWindowStart(LocalDateTime.of(2026, 7, 31, 23, 45)); window.setWindowEnd(LocalDateTime.of(2026, 8, 1, 0, 0));
        assertThatThrownBy(() -> PostLoginFeatureExport.fromObserved(attempt, List.of(), List.of(window))).isInstanceOf(IllegalArgumentException.class);
        window.setAccountId("owned-account"); window.setWindowEnd(LocalDateTime.of(2026, 8, 1, 0, 15));
        assertThatThrownBy(() -> PostLoginFeatureExport.fromObserved(attempt, List.of(), List.of(window))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void bothRepresentationsUseOnlyThePrefixBeforeTheCurrentAttempt() throws Exception {
        var frame = frame();
        var before = PostLoginFeatureExport.transform(frame);
        var future = event("DOMAIN_ACTION", "PASSWORD_CHANGE", "SUCCESS", "2026-08-01T00:00:20Z");
        frame.withArray("context").add(future);
        assertThat(PostLoginFeatureExport.transform(frame)).isEqualTo(before);
        assertThat(before).containsEntry("data_provenance", "DEMO_ONLY").containsEntry("before_current_outcome", true);
        @SuppressWarnings("unchecked") var base = (List<Double>) before.get("baseline_features");
        assertThat(base).hasSize(37); assertThat(base.get(0)).isEqualTo(1); assertThat(base.get(5)).isZero();
        @SuppressWarnings("unchecked") var post = (List<Double>) before.get("postlogin_features");
        assertThat(post).hasSize(20); assertThat(post.subList(0, 4)).containsExactly(1.0, 0.0, 1.0, 1.0);
        assertThat(post.get(7)).isZero();
    }

    @Test void emptyCurrentWindowPrefixDoesNotInventALoginOrDropThePriorSession() throws Exception {
        var frame = frame(); frame.withArray("context").removeAll();
        ((ObjectNode) frame.path("attempt")).put("event_timestamp", "2026-08-01T00:15:01Z");
        frame.withArray("context").add(event("AUTH", "LOGIN", "SUCCESS", "2026-08-01T00:14:59Z"));
        var row = PostLoginFeatureExport.transform(frame);
        @SuppressWarnings("unchecked") var base = (List<Double>) row.get("baseline_features");
        @SuppressWarnings("unchecked") var post = (List<Double>) row.get("postlogin_features");
        assertThat(base.get(4)).isZero(); assertThat(post.get(3)).isEqualTo(1); assertThat(post.get(5)).isEqualTo(2);
    }

    @Test void labelsSecretsAndFutureBaselineFramesAreRejectedAtTransportBoundary() throws Exception {
        var labelled = frame(); labelled.put("label", 1);
        assertThatThrownBy(() -> PostLoginFeatureExport.transform(labelled)).isInstanceOf(IllegalArgumentException.class);
        var secret = frame(); ((ObjectNode) secret.path("attempt")).put("token", "must-not-enter-model");
        assertThatThrownBy(() -> PostLoginFeatureExport.transform(secret)).isInstanceOf(IllegalArgumentException.class);
        var future = frame();
        future.withArray("baseline_frames").addObject().put("account_id", "owned-account").put("window_start", "2026-08-01T00:15:00Z");
        assertThatThrownBy(() -> PostLoginFeatureExport.transform(future)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void streamedWarmupAndEmbeddedWarmupHaveTheSamePastOnlyResult() throws Exception {
        var frame = frame();
        var prior = JSON.createObjectNode(); prior.put("frame_id", "owned-prior-frame").put("account_id", "owned-account")
                .put("day", 1).put("cohort", "COLD").put("window_start", "2026-07-31T23:45:00Z")
                .put("demo_label", "NORMAL").put("family", "normal").put("telemetry_contract_version", 3);
        var request = event("HTTP_REQUEST", "API_REQUEST", "SUCCESS", "2026-07-31T23:45:01Z");
        request.remove(List.of("actor_user_id", "session_pseudonym", "session_issued_at", "telemetry_contract_version"));
        request.put("http_status", 200).put("http_method", "GET").put("route_group", "profile").put("endpoint_category", "PROFILE_READ");
        prior.putArray("events").add(request);
        frame.withArray("baseline_frames").add(prior);
        var embedded = PostLoginFeatureExport.transform(frame);
        var history = new UebaFeatureExport.History();
        UebaFeatureExport.transform(prior, history, 4);
        frame.withArray("baseline_frames").removeAll();
        assertThat(PostLoginFeatureExport.transform(frame, history)).isEqualTo(embedded);
    }

    private static ObjectNode frame() throws Exception {
        var frame = JSON.createObjectNode(); frame.put("frame_id", "postlogin-export-owned-frame");
        frame.set("attempt", event("SENSITIVE_ACTION_ATTEMPT", "PASSWORD_CHANGE", "ATTEMPT", "2026-08-01T00:00:20Z"));
        var context = frame.putArray("context");
        context.add(event("AUTH", "LOGIN", "SUCCESS", "2026-08-01T00:00:01Z"));
        var request = event("HTTP_REQUEST", "API_REQUEST", "SUCCESS", "2026-08-01T00:00:10Z");
        request.put("telemetry_contract_version", 3).put("http_status", 200).put("http_method", "GET")
                .put("endpoint_category", "PROFILE_READ").put("route_group", "profile");
        context.add(request); frame.putArray("baseline_frames"); return frame;
    }

    private static ObjectNode event(String type, String action, String outcome, String timestamp) {
        var value = JSON.createObjectNode(); value.put("actor_user_id", "owned-account");
        value.put("event_type", type); value.put("action", action); value.put("outcome", outcome);
        value.put("event_timestamp", timestamp); value.put("telemetry_contract_version", 4);
        value.put("session_pseudonym", "a".repeat(64)); value.put("session_issued_at", "2026-08-01T00:00:00Z");
        return value;
    }

    private static SiemSecurityEvent observed(com.fasterxml.jackson.databind.JsonNode value) {
        var event = new SiemSecurityEvent(); event.setActorUserId(value.path("actor_user_id").asText());
        event.setEventType(value.path("event_type").asText()); event.setAction(value.path("action").asText());
        event.setOutcome(value.path("outcome").asText());
        event.setEventTimestamp(LocalDateTime.ofInstant(Instant.parse(value.path("event_timestamp").asText()), ZoneOffset.UTC));
        event.setTelemetryContractVersion(value.path("telemetry_contract_version").asInt());
        event.setSessionPseudonym(value.path("session_pseudonym").asText());
        event.setSessionIssuedAt(LocalDateTime.ofInstant(Instant.parse(value.path("session_issued_at").asText()), ZoneOffset.UTC));
        if (value.has("http_status")) event.setHttpStatus(value.path("http_status").asInt());
        if (value.has("http_method")) event.setHttpMethod(value.path("http_method").asText());
        if (value.has("route_group")) event.setRouteGroup(value.path("route_group").asText());
        if (value.has("endpoint_category")) event.setEndpointCategory(value.path("endpoint_category").asText());
        return event;
    }
}
