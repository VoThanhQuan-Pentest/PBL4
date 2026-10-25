package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SessionEndpointBehaviorFeaturesTest {
    private static final LocalDateTime START = LocalDateTime.of(2026, 10, 1, 0, 0);
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");
    private static final String SESSION_A = "a".repeat(64), SESSION_B = "b".repeat(64);
    private static final AccountBaselinePolicy.Snapshot COLD = AccountBaselinePolicy.summarize(List.of(), START, ZONE);
    private static final AccountBaselinePolicy.ObservedRequestHistory EMPTY = AccountBaselinePolicy.observedRequests(List.of(), START);

    @Test void preservesAllTwentyFiveSchema3DimensionsAndLeavesLegacyMetadataUncovered() {
        var old = request(0, "PRODUCT_LIST", "GET", SESSION_A);
        old.setTelemetryContractVersion(null); old.setEndpointCategory(null);
        old.setSessionPseudonym(null); old.setSessionIssuedAt(null);
        var events = List.of(old);
        var contextual = contextual(events);
        var current = features(events);
        assertThat(current.featureSchemaVersion()).isEqualTo(4);
        assertThat(current.values()).hasSize(37);
        assertThat(current.values().subList(0, 25)).isEqualTo(contextual.values());
        assertThat(current.values().subList(25, 37)).containsOnly(0.0);
        assertThat(AccountBehaviorFeatures.names(4).subList(0, 25)).isEqualTo(AccountBehaviorFeatures.names(3));
        assertThat(AccountBehaviorFeatures.names(4).subList(25, 37)).containsExactly(
                "endpoint_metadata_count", "distinct_endpoint_category_count", "unmatched_endpoint_request_count",
                "unresolved_endpoint_request_count", "write_request_count", "same_endpoint_peak_10s",
                "session_metadata_count", "distinct_authenticated_session_count", "minimum_authenticated_session_age_seconds",
                "workflow_transition_count", "prior_request_window_count", "short_history_request_log_ratio");
    }

    @Test void separatesUnmatchedUnresolvedAndMissingMetadataWithoutGuessingFromLegacyRoute() {
        var matched = request(0, "PRODUCT_LIST", "GET", null);
        var write = request(1, "PROFILE_UPDATE", "PUT", null);
        var unmatched = request(2, "UNMATCHED", "POST", null);
        var unresolved = request(3, "UNRESOLVED", "DELETE", null);
        var other = request(4, "OTHER_MATCHED", "PATCH", null);
        var unknown = request(5, "/api/products/raw-id", "POST", null);
        var legacy = request(6, "PROFILE_UPDATE", "POST", null); legacy.setTelemetryContractVersion(2);
        var absent = request(7, null, "POST", null);
        var values = features(List.of(matched, write, unmatched, unresolved, other, unknown, legacy, absent)).values();
        assertThat(values.subList(25, 31)).containsExactly(5.0, 3.0, 1.0, 1.0, 2.0, 1.0);
        assertThat(values.subList(31, 35)).containsExactly(0.0, 0.0, 0.0, 0.0);
    }

    @Test void sameEndpointPeakUsesExactRollingIntervalAndExcludesSentinels() {
        var events = List.of(request(0, "PRODUCT_LIST", "GET", null), request(9, "PRODUCT_LIST", "GET", null),
                request(10, "PRODUCT_LIST", "GET", null), request(11, "PRODUCT_LIST", "GET", null),
                request(9, "PRODUCT_DETAIL", "GET", null), request(9, "UNMATCHED", "GET", null),
                request(9, "UNRESOLVED", "GET", null));
        assertThat(features(events).values().get(30)).isEqualTo(3.0);
    }

    @Test void sessionCoverageRequiresValidAuthenticatedServerMetadataAndAgeIsObservedThenCapped() {
        var a = request(0, "PRODUCT_LIST", "GET", SESSION_A); a.setSessionIssuedAt(START.minusDays(7));
        var b = request(1, "PRODUCT_DETAIL", "GET", SESSION_A); b.setSessionIssuedAt(START.minusDays(7));
        var c = request(2, null, "GET", SESSION_B); c.setSessionIssuedAt(START.minusSeconds(48));
        var invalid = request(3, "PRODUCT_LIST", "GET", "raw-jti");
        var future = request(4, "PRODUCT_LIST", "GET", SESSION_A); future.setSessionIssuedAt(START.plusSeconds(5));
        var unauthenticated = request(5, "PRODUCT_LIST", "GET", SESSION_A); unauthenticated.setActorUserId(null);
        var legacy = request(6, "PRODUCT_LIST", "GET", SESSION_A); legacy.setTelemetryContractVersion(1);
        var values = features(List.of(a, b, c, invalid, future, unauthenticated, legacy)).values();
        assertThat(values.subList(31, 34)).containsExactly(3.0, 2.0, 50.0);
        assertThat(features(List.of(a)).values().get(33)).isEqualTo(86400.0);
        var justIssued = request(0, "PRODUCT_LIST", "GET", SESSION_A); justIssued.setSessionIssuedAt(START);
        assertThat(features(List.of(justIssued)).values().get(33)).isZero();
    }

    @ParameterizedTest @MethodSource("workflowPairs")
    void workflowMotifsRequireSameAuthenticatedSessionAndAllowTheExact120SecondBoundary(String left, String right) {
        assertThat(features(List.of(request(0, left, "GET", SESSION_A), request(120, right, "POST", SESSION_A)))
                .values().get(34)).isEqualTo(1.0);
    }

    static Stream<Arguments> workflowPairs() {
        return Stream.of(Arguments.of("PRODUCT_LIST", "PRODUCT_DETAIL"), Arguments.of("PROFILE_READ", "PROFILE_UPDATE"),
                Arguments.of("PROFILE_READ", "PROFILE_EMAIL_OTP"), Arguments.of("PROFILE_READ", "PROFILE_PASSWORD"),
                Arguments.of("ORDERS_READ", "ORDER_CANCEL"), Arguments.of("ORDERS_READ", "ORDER_RETURN"),
                Arguments.of("SUPPORT_READ", "SUPPORT_SEND"), Arguments.of("REVIEW_READ", "REVIEW_CREATE"),
                Arguments.of("PROMO_LIST", "PROMO_CLAIM"), Arguments.of("SYNC_READ", "SYNC_WRITE"));
    }

    @Test void failedCrossSessionStaleAndAmbiguouslyTiedRequestsDoNotInventWorkflowTransitions() {
        var left = request(0, "PROFILE_READ", "GET", SESSION_A);
        var failed = request(1, "PROFILE_UPDATE", "PUT", SESSION_A); failed.setHttpStatus(403);
        assertThat(features(List.of(left, failed)).values().get(34)).isZero();
        assertThat(features(List.of(left, request(1, "PROFILE_UPDATE", "PUT", SESSION_B))).values().get(34)).isZero();
        assertThat(features(List.of(left, request(121, "PROFILE_UPDATE", "PUT", SESSION_A))).values().get(34)).isZero();
        assertThat(features(List.of(left, request(0, "PROFILE_UPDATE", "PUT", SESSION_A))).values().get(34)).isZero();
        var tied = List.of(left, request(1, "PROFILE_READ", "GET", SESSION_A),
                request(1, "PRODUCT_LIST", "GET", SESSION_A), request(2, "PROFILE_UPDATE", "PUT", SESSION_A));
        assertThat(features(tied).values().get(34)).isZero();
        assertThat(features(List.of(left, failed, request(2, "PROFILE_UPDATE", "PUT", SESSION_A))).values().get(34)).isZero();
    }

    @Test void labelsIdentifiersInputOrderAndBijectiveSessionRenamingDoNotDetermineNumericFeatures() {
        var events = new ArrayList<>(List.of(request(0, "PRODUCT_LIST", "GET", SESSION_A),
                request(1, "PRODUCT_DETAIL", "GET", SESSION_A), request(2, "PROFILE_READ", "GET", SESSION_B)));
        var expected = features(events);
        events.forEach(event -> {
            event.setId("ignored-event"); event.setTraceId("ignored-trace"); event.setDemoLabel("ABNORMAL");
            event.setActorUserId("renamed-account"); event.setTargetUserId("ignored-target");
            event.setSessionPseudonym(SESSION_A.equals(event.getSessionPseudonym()) ? "c".repeat(64) : "d".repeat(64));
        });
        Collections.reverse(events);
        assertThat(features(events).values()).isEqualTo(expected.values());
    }

    @Test void shortObservedHistoryUsesLogDifferenceWithoutBaselineReadinessOrMadNormalization() {
        var events = List.of(request(0, "PRODUCT_LIST", "GET", null));
        var history = new AccountBaselinePolicy.ObservedRequestHistory(1, Math.log1p(99));
        var values = SessionEndpointBehaviorFeatures.fromEvents(contextual(events), history, START, events).values();
        assertThat(values.get(35)).isEqualTo(1);
        assertThat(values.get(36)).isCloseTo(Math.log1p(1) - Math.log1p(99), within(1e-12));
        assertThat(SessionEndpointBehaviorFeatures.fromEvents(contextual(events),
                new AccountBaselinePolicy.ObservedRequestHistory(1, 100), START, events).values().get(36)).isEqualTo(-20);
    }

    @Test void invalidCountsCoverageSessionAgeAndFutureSourceWindowsAreRejected() {
        var event = request(0, "PRODUCT_LIST", "GET", SESSION_A);
        var valid = features(List.of(event));
        for (int index : new int[] {25, 26, 27, 28, 29, 30, 31, 32, 34, 35}) {
            var values = new ArrayList<>(valid.values()); values.set(index, 1.5);
            assertThatThrownBy(() -> new AccountBehaviorFeatures.Vector(4, values)).isInstanceOf(IllegalArgumentException.class);
        }
        for (var mutation : List.of(new double[] {25, 2}, new double[] {27, 2}, new double[] {32, 2},
                new double[] {34, 1}, new double[] {33, 86401}, new double[] {35, 1345}, new double[] {36, 21})) {
            var values = new ArrayList<>(valid.values()); values.set((int) mutation[0], mutation[1]);
            assertThatThrownBy(() -> new AccountBehaviorFeatures.Vector(4, values)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> SessionEndpointBehaviorFeatures.fromEvents(contextual(List.of(event)), EMPTY, START, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        var outside = request(900, "PRODUCT_LIST", "GET", SESSION_A);
        assertThatThrownBy(() -> SessionEndpointBehaviorFeatures.fromEvents(contextual(List.of(event)), EMPTY, START, List.of(outside)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    static AccountBehaviorFeatures.Vector contextual(List<SiemSecurityEvent> events) {
        var personal = AccountBehaviorFeatures.withPersonalFeatures(AccountBehaviorFeatures.fromEvents(events, COLD.features(), ZONE), COLD);
        return ContextualBehaviorFeatures.fromEvents(personal, COLD, events);
    }

    static AccountBehaviorFeatures.Vector features(List<SiemSecurityEvent> events) {
        return SessionEndpointBehaviorFeatures.fromEvents(contextual(events), EMPTY, START, events);
    }

    static SiemSecurityEvent request(int seconds, String category, String method, String session) {
        var event = new SiemSecurityEvent(); event.setEventTimestamp(START.plusSeconds(seconds)); event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST"); event.setHttpStatus(200); event.setHttpMethod(method); event.setRouteGroup("products");
        event.setSourceIp("203.0.113.1"); event.setActorUserId("owned-account"); event.setTelemetryContractVersion(3);
        event.setEndpointCategory(category); event.setSessionPseudonym(session);
        event.setSessionIssuedAt(session == null ? null : START.minusMinutes(1));
        return event;
    }
}
