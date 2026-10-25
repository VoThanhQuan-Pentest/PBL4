package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AccountBehaviorFeaturesTest {
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    @Test
    void preservesTheElevenFeatureContractAndMarksNovelActivityAgainstEstablishedHistory() {
        List<SiemSecurityEvent> events = List.of(
                event("HTTP_REQUEST", "API_REQUEST", "FAILURE", 403, "orders", "203.0.113.2", "FIREFOX"),
                event("HTTP_REQUEST", "API_REQUEST", "FAILURE", 503, "profile", "203.0.113.2", "FIREFOX"),
                event("AUTH", "LOGIN", "FAILURE", null, null, "203.0.113.2", null),
                event("AUTH", "LOGIN", "SUCCESS", null, null, "203.0.113.2", null),
                event("DOMAIN_ACTION", "PASSWORD_CHANGE", "SUCCESS", null, null, null, null));
        AccountBehaviorFeatures.Baseline baseline = new AccountBehaviorFeatures.Baseline(true,
                Set.of("198.51.100.1"), Set.of("CHROMIUM"), Set.of(9, 10));

        AccountBehaviorFeatures.Vector vector = AccountBehaviorFeatures.fromEvents(events, baseline, ZONE);

        assertThat(AccountBehaviorFeatures.NAMES).hasSize(11);
        assertThat(vector.featureSchemaVersion()).isEqualTo(1);
        assertThat(vector.values()).containsExactly(2.0, 1.0, 1.0, 1.0, 1.0, 1.0,
                2.0, 1.0, 1.0, 1.0, 1.0);
    }

    @Test
    void coldStartDoesNotPretendThatEveryNewIpOrHourIsAnAnomaly() {
        AccountBehaviorFeatures.Vector vector = AccountBehaviorFeatures.fromEvents(
                List.of(event("AUTH", "LOGIN", "SUCCESS", null, null, "203.0.113.2", "FIREFOX")),
                AccountBehaviorFeatures.Baseline.insufficientHistory(), ZONE);
        assertThat(vector.values().subList(8, 11)).containsExactly(0.0, 0.0, 0.0);
    }

    @Test
    void rejectsMalformedEvidenceRatherThanBuildingAnInvalidTrainingSample() {
        SiemSecurityEvent missingTimestamp = new SiemSecurityEvent();
        assertThatThrownBy(() -> AccountBehaviorFeatures.fromEvents(
                List.of(missingTimestamp), AccountBehaviorFeatures.Baseline.insufficientHistory(), ZONE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static SiemSecurityEvent event(String type, String action, String outcome, Integer status,
                                           String route, String ip, String userAgent) {
        SiemSecurityEvent value = new SiemSecurityEvent();
        value.setEventTimestamp(LocalDateTime.of(2026, 9, 26, 1, 30)); // 08:30 local
        value.setEventType(type);
        value.setAction(action);
        value.setOutcome(outcome);
        value.setHttpStatus(status);
        value.setRouteGroup(route);
        value.setSourceIp(ip);
        value.setUserAgentFamily(userAgent);
        return value;
    }
}
