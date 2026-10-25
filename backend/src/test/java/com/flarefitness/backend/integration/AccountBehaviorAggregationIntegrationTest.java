package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.siem.AccountBehaviorAggregationWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorScoringWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SiemAccountWatchService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AccountBehaviorAggregationIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private UserRepository users;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private AccountBehaviorAggregationWorker aggregation;
    @Autowired private AccountBehaviorScoringWorker scoring;
    @Autowired private SiemAccountWatchService watch;

    @Test
    void lateEventsRebuildTheSameWindowWithoutDoubleCounting() {
        String accountId = "ueba-test-" + UUID.randomUUID().toString().substring(0, 8);
        LocalDateTime past = LocalDateTime.now(ZoneOffset.UTC).minusHours(2);
        LocalDateTime start = past.withMinute(0).withSecond(0).withNano(0);
        createCustomer(accountId);

        SiemSecurityEvent first = request(accountId, start.plusMinutes(1), 200);
        events.saveAndFlush(first);
        aggregation.aggregatePendingAt(LocalDateTime.now(ZoneOffset.UTC));
        SiemAccountBehaviorWindow original = windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(
                accountId, start, 1).orElseThrow();
        assertThat(original.featureVector()).startsWith(1.0, 0.0, 0.0);
        assertThat(original.isBaselineEstablished()).isFalse();
        assertThat(events.findById(first.getId()).orElseThrow().getAggregatedAt()).isNotNull();

        SiemSecurityEvent late = request(accountId, start.plusMinutes(2), 403);
        events.saveAndFlush(late);
        aggregation.aggregatePendingAt(LocalDateTime.now(ZoneOffset.UTC));
        SiemAccountBehaviorWindow rebuilt = windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(
                accountId, start, 1).orElseThrow();
        assertThat(rebuilt.getId()).isEqualTo(original.getId());
        assertThat(rebuilt.getEventCount()).isEqualTo(2);
        assertThat(rebuilt.featureVector()).startsWith(2.0, 1.0, 0.0);
        assertThat(windows.countByAccountId(accountId)).isEqualTo(1);
    }

    @Test
    void ruleOnlyScoringCreatesOneHumanReviewedCaseWithoutRevokingSessions() {
        String accountId = "ueba-score-" + UUID.randomUUID().toString().substring(0, 8);
        LocalDateTime past = LocalDateTime.now(ZoneOffset.UTC).minusHours(3);
        LocalDateTime start = past.withMinute(0).withSecond(0).withNano(0);
        createCustomer(accountId);
        for (int index = 0; index < 130; index++) {
            events.save(request(accountId, start.plusSeconds(index), index < 11 ? 403 : 200));
        }
        for (int index = 0; index < 6; index++) {
            SiemSecurityEvent failed = request(accountId, start.plusMinutes(5).plusSeconds(index), 401);
            failed.setActorUserId(null);
            failed.setTargetUserId(accountId);
            failed.setEventType("AUTH");
            failed.setAction("LOGIN");
            failed.setOutcome("FAILURE");
            failed.setHttpStatus(null);
            events.save(failed);
        }
        events.flush();

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        aggregation.aggregatePendingAt(now);
        scoring.scorePendingAt(now);
        scoring.scorePendingAt(now.plusSeconds(1));

        assertThat(incidents.countByTargetUserIdAndOrigin(accountId, IncidentOrigin.UEBA)).isEqualTo(1);
        assertThat(windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(accountId, start, 1)
                .orElseThrow().getRiskScore()).isGreaterThanOrEqualTo(45);
        assertThat(watch.watchlist(now.minusDays(1), now.plusMinutes(1), 0, 50).content())
                .anyMatch(item -> accountId.equals(item.accountId()));
        assertThat(watch.behavior(accountId, now.minusDays(1), now.plusMinutes(1), 0, 50)
                .content().getFirst().features()).containsKey("failed_login_count");
        assertThat(users.findById(accountId).orElseThrow().getAuthVersion()).isZero();
        String incidentId = incidents.findByGroupingKey("ueba:" + accountId + ":" + start)
                .orElseThrow().getId();
        var evidence = watch.incidentEvents(incidentId, 0, 200);
        assertThat(evidence.totalElements()).isEqualTo(136);
        assertThat(evidence.content()).anyMatch(event ->
                "LOGIN".equals(event.action()) && "FAILURE".equals(event.outcome()));
        assertThat(evidence.content()).anyMatch(event -> Integer.valueOf(403).equals(event.httpStatus()));
        assertThat(watch.incidentWindows(incidentId, 0, 20).content())
                .anyMatch(window -> window.riskScore() != null && window.riskScore() >= 45);

        SiemAccountBehaviorWindow nextWindow = new SiemAccountBehaviorWindow();
        nextWindow.setId("ueba-next-" + UUID.randomUUID());
        nextWindow.setAccountId(accountId);
        nextWindow.setWindowStart(start.plusMinutes(15));
        nextWindow.setWindowEnd(start.plusMinutes(30));
        nextWindow.setCreatedAt(now);
        nextWindow.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                java.util.List.of(130.0, 11.0, 0.0, 6.0, 0.0, 0.0, 2.0, 1.0, 0.0, 0.0, 0.0)),
                136, false, "203.0.113.11", "FIREFOX", "ABNORMAL", now);
        windows.saveAndFlush(nextWindow);
        scoring.scorePendingAt(now);
        scoring.scorePendingAt(now.plusSeconds(1));
        assertThat(incidents.countByTargetUserIdAndOrigin(accountId, IncidentOrigin.UEBA)).isEqualTo(1);
        assertThat(incidents.findByGroupingKey("ueba:" + accountId + ":" + start)
                .orElseThrow().getAlertCount()).isEqualTo(2);
    }

    private void createCustomer(String accountId) {
        User customer = new User();
        customer.setId(accountId);
        customer.setUsername(accountId);
        customer.setPassword("not-used-by-test");
        customer.setRole("CUSTOMER");
        customer.setHoTen("UEBA fixture");
        customer.setStatus("Hoat dong");
        customer.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(customer);
    }

    private SiemSecurityEvent request(String accountId, LocalDateTime at, int status) {
        SiemSecurityEvent event = new SiemSecurityEvent();
        event.setId(UUID.randomUUID().toString());
        event.setEventTimestamp(at);
        event.setActorUserId(accountId);
        event.setSourceIp("203.0.113.10");
        event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST");
        event.setOutcome(status >= 400 ? "FAILURE" : "SUCCESS");
        event.setRouteGroup("products");
        event.setHttpMethod("GET");
        event.setHttpStatus(status);
        event.setUserAgentFamily("CHROMIUM");
        event.setCreatedAt(at);
        return event;
    }
}
