package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemResponseActionRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.siem.SiemIncidentService;
import com.flarefitness.backend.service.siem.SiemContainmentService;
import com.flarefitness.backend.service.siem.SiemResponseActionService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;

/** 5 observed families x 10 evidence variants x 10 real persisted SOC paths.
 * Workflow correctness only: these 500 cases are NOT ML accuracy samples. */
@SpringBootTest
class SocWorkflowMatrixIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private UserRepository users;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private SiemIncidentHistoryRepository history;
    @Autowired private SiemResponseActionRepository actions;
    @Autowired private SiemIncidentService workflow;
    @Autowired private SiemResponseActionService responses;
    @Autowired private SiemContainmentService containment;

    enum Path { CLAIM, ESCALATE, CLOSE_TP, CLOSE_FP, RETURN, FORBIDDEN, STALE, COMPETING_CLAIM, SESSION_IDEMPOTENT, REOPEN }

    static Stream<Arguments> cases() {
        return Stream.of("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
                .flatMap(family -> java.util.stream.IntStream.range(0, 10).boxed()
                        .flatMap(variant -> Stream.of(Path.values()).map(path -> Arguments.of(family, variant, path))));
    }

    @ParameterizedTest(name = "{0}/evidence-{1}/{2}")
    @MethodSource("cases")
    @Transactional
    void realPersistedTransitionsPreserveActorPermissionsHistoryAndIdempotency(String family, int variant, Path path) {
        String suffix = family.substring(0, 4) + "-" + variant + "-" + path.ordinal();
        User customer = user("customer-" + suffix, "CUSTOMER");
        User l1 = user("l1-" + suffix, "SOC L1"), l2 = user("l2-" + suffix, "SOC L2"), other = user("other-" + suffix, "SOC L1");
        SiemIncident incident = incident(family, variant, suffix, customer.getId());
        if (List.of(Path.RETURN, Path.FORBIDDEN, Path.SESSION_IDEMPOTENT).contains(path)) incident.setQueueTier(IncidentQueueTier.L2);
        incidents.saveAndFlush(incident);
        long initialVersion = incident.getVersion();
        String reason = "Owned matrix timeline/evidence variant " + variant;
        switch (path) {
            case CLAIM -> {
                var result = transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                assertThat(result.status()).isEqualTo(IncidentStatus.IN_PROGRESS);
                assertThat(result.assigneeUserId()).isEqualTo(l1.getId());
                assertActions(incident, "CLAIM");
            }
            case ESCALATE -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                var result = transition(incident, SiemDtos.TransitionAction.ESCALATE, l1, reason, null);
                assertThat(result.queueTier()).isEqualTo(IncidentQueueTier.L2);
                assertThat(result.status()).isEqualTo(IncidentStatus.NEW); assertThat(result.assigneeUserId()).isNull();
                assertActions(incident, "CLAIM", "ESCALATE");
            }
            case CLOSE_TP, CLOSE_FP -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                transition(incident, SiemDtos.TransitionAction.ESCALATE, l1, reason, null);
                transition(incident, SiemDtos.TransitionAction.CLAIM, l2, null, null);
                IncidentConclusion conclusion = path == Path.CLOSE_TP ? IncidentConclusion.TRUE_POSITIVE : IncidentConclusion.FALSE_POSITIVE;
                if (path == Path.CLOSE_TP) verifyNoResponseRequired(incident, l2, reason);
                var result = transition(incident, SiemDtos.TransitionAction.CLOSE, l2, reason, conclusion);
                assertThat(result.status()).isEqualTo(IncidentStatus.CLOSED); assertThat(result.conclusion()).isEqualTo(conclusion);
                assertThat(result.assigneeUserId()).isEqualTo(l2.getId());
                if (path == Path.CLOSE_TP) assertActions(incident, "CLAIM", "ESCALATE", "CLAIM", "RESPONSE_RECOVERY_VERIFIED", "CLOSE");
                else assertActions(incident, "CLAIM", "ESCALATE", "CLAIM", "CLOSE");
            }
            case RETURN -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l2, null, null);
                var result = transition(incident, SiemDtos.TransitionAction.RETURN_TO_L1, l2, reason, null);
                assertThat(result.queueTier()).isEqualTo(IncidentQueueTier.L1);
                assertThat(result.status()).isEqualTo(IncidentStatus.NEW); assertThat(result.assigneeUserId()).isNull();
                assertActions(incident, "CLAIM", "RETURN_TO_L1");
            }
            case FORBIDDEN -> {
                User denied = variant % 2 == 0 ? customer : l1;
                assertThatThrownBy(() -> transition(incident, SiemDtos.TransitionAction.CLAIM, denied, null, null))
                        .isInstanceOf(AccessDeniedException.class);
                assertThat(incidents.findById(incident.getId()).orElseThrow().getStatus()).isEqualTo(IncidentStatus.NEW);
                assertThat(history.findTop100ByIncidentIdOrderByCreatedAtDesc(incident.getId())).isEmpty();
            }
            case STALE -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                assertThatThrownBy(() -> workflow.transitionIncident(incident.getId(),
                        new SiemDtos.TransitionIncident(initialVersion, SiemDtos.TransitionAction.ESCALATE, reason, null), auth(l1)))
                        .isInstanceOf(ConflictException.class);
                assertActions(incident, "CLAIM");
            }
            case COMPETING_CLAIM -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                assertThatThrownBy(() -> transition(incident, SiemDtos.TransitionAction.CLAIM, other, null, null))
                        .isInstanceOf(ConflictException.class);
                assertThat(incidents.findById(incident.getId()).orElseThrow().getAssigneeUserId()).isEqualTo(l1.getId());
                assertActions(incident, "CLAIM");
            }
            case SESSION_IDEMPOTENT -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l2, null, null);
                var request = new SiemDtos.RevokeSessions(incidents.findById(incident.getId()).orElseThrow().getVersion(), "matrix-request-" + suffix, reason);
                var first = responses.revokeCustomerSessions(incident.getId(), request, auth(l2));
                var again = responses.revokeCustomerSessions(incident.getId(), request, auth(l2));
                assertThat(again.id()).isEqualTo(first.id()); assertThat(first.newAuthVersion()).isEqualTo(1);
                assertThat(users.findById(customer.getId()).orElseThrow().getAuthVersion()).isEqualTo(1);
                assertThat(actions.findByRequestId(request.requestId())).isPresent();
                assertActions(incident, "CLAIM", "CUSTOMER_SESSIONS_REVOKED");
            }
            case REOPEN -> {
                transition(incident, SiemDtos.TransitionAction.CLAIM, l1, null, null);
                transition(incident, SiemDtos.TransitionAction.ESCALATE, l1, reason, null);
                transition(incident, SiemDtos.TransitionAction.CLAIM, l2, null, null);
                verifyNoResponseRequired(incident, l2, reason);
                transition(incident, SiemDtos.TransitionAction.CLOSE, l2, reason, IncidentConclusion.TRUE_POSITIVE);
                var result = transition(incident, SiemDtos.TransitionAction.REOPEN, l2, reason, null);
                assertThat(result.status()).isEqualTo(IncidentStatus.NEW); assertThat(result.assigneeUserId()).isNull();
                assertThat(result.conclusion()).isEqualTo(IncidentConclusion.UNREVIEWED);
                assertActions(incident, "CLAIM", "ESCALATE", "CLAIM", "RESPONSE_RECOVERY_VERIFIED", "CLOSE", "REOPEN");
            }
        }
    }

    private void verifyNoResponseRequired(SiemIncident incident, User analyst, String reason) {
        long version = incidents.findById(incident.getId()).orElseThrow().getVersion();
        assertThatThrownBy(() -> transition(incident, SiemDtos.TransitionAction.CLOSE, analyst,
                reason, IncidentConclusion.TRUE_POSITIVE)).isInstanceOf(ConflictException.class);
        containment.verify(incident.getId(), new SiemContainmentService.Verification(
                java.util.UUID.randomUUID().toString(), version,
                "Workflow-only fixture has no containment action requiring recovery.", "NOT_REQUIRED", "NOT_REQUIRED"), auth(analyst));
    }

    private SiemDtos.Incident transition(SiemIncident incident, SiemDtos.TransitionAction action, User actor, String reason, IncidentConclusion conclusion) {
        long version = incidents.findById(incident.getId()).orElseThrow().getVersion();
        return workflow.transitionIncident(incident.getId(), new SiemDtos.TransitionIncident(version, action, reason, conclusion), auth(actor));
    }

    @Test
    void twoActualConcurrentTransactionsCannotBothClaimOneIncident() throws Exception {
        String suffix = "race-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        User target = user("customer-" + suffix, "CUSTOMER");
        User first = user("l1-first-" + suffix, "SOC L1"), second = user("l1-second-" + suffix, "SOC L1");
        SiemIncident incident = incidents.saveAndFlush(incident("request_burst", 0, suffix, target.getId()));
        long version = incident.getVersion();
        var barrier = new java.util.concurrent.CyclicBarrier(2);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Boolean> one = () -> raceClaim(incident.getId(), version, first, barrier);
            java.util.concurrent.Callable<Boolean> two = () -> raceClaim(incident.getId(), version, second, barrier);
            var a = executor.submit(one); var b = executor.submit(two);
            assertThat(List.of(a.get(10, java.util.concurrent.TimeUnit.SECONDS), b.get(10, java.util.concurrent.TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
        var stored = incidents.findById(incident.getId()).orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(IncidentStatus.IN_PROGRESS);
        assertThat(stored.getAssigneeUserId()).isIn(first.getId(), second.getId());
        assertActions(stored, "CLAIM");
    }

    private boolean raceClaim(String id, long version, User actor, java.util.concurrent.CyclicBarrier barrier) throws Exception {
        barrier.await(5, java.util.concurrent.TimeUnit.SECONDS);
        try {
            workflow.transitionIncident(id, new SiemDtos.TransitionIncident(version, SiemDtos.TransitionAction.CLAIM, null, null), auth(actor));
            return true;
        } catch (ConflictException | org.springframework.orm.ObjectOptimisticLockingFailureException expected) {
            return false;
        }
    }

    private void assertActions(SiemIncident incident, String... expected) {
        var records = history.findTop100ByIncidentIdOrderByCreatedAtDesc(incident.getId());
        assertThat(records).extracting(SiemIncidentHistory::getAction).containsExactlyInAnyOrder(expected);
        assertThat(records).allSatisfy(row -> {
            assertThat(row.getActorUserId()).isNotBlank(); assertThat(row.getCreatedAt()).isNotNull();
            assertThat(row.getNewValue()).isNotBlank();
        });
    }

    private User user(String id, String role) {
        User value = new User(); value.setId(id); value.setUsername(id.replace('-', '_')); value.setPassword("not-used-by-owned-workflow-matrix");
        value.setRole(role); value.setStatus("Hoat dong"); value.setDeleted(false); value.setHoTen("Owned SOC matrix actor");
        value.setAuthVersion(0L); value.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC)); return users.saveAndFlush(value);
    }
    private UsernamePasswordAuthenticationToken auth(User value) {
        var principal = new CurrentUserPrincipal(value);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
    private SiemIncident incident(String family, int variant, String suffix, String customer) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemIncident value = new SiemIncident(); value.setId("matrix-incident-" + suffix); value.setGroupingKey("matrix-group-" + suffix);
        value.setTitle(family + " owned evidence variant " + variant); value.setServiceId("flare-web"); value.setRuleId("FLARE_UEBA_" + family);
        value.setOrigin(IncidentOrigin.UEBA); value.setTargetUserId(customer); value.setQueueTier(IncidentQueueTier.L1);
        value.setBucketStart(now.minusHours(1)); value.setSourceIp("198.51.100." + (variant + 1)); value.setSourceSeverity("high");
        value.setScore(45 + variant * 5); value.setSeverity(IncidentSeverity.values()[variant % IncidentSeverity.values().length]);
        value.setClassification(variant % 2 == 0 ? IncidentClassification.INVESTIGATE : IncidentClassification.POTENTIAL_NOISE);
        value.setClassificationReason("Owned mixed evidence"); value.setMissingData(variant % 3 == 0);
        value.setStatus(IncidentStatus.NEW); value.setConclusion(IncidentConclusion.UNREVIEWED); value.setManualInvestigateOverride(false);
        value.setAlertCount(variant + 1); value.setDistinctRuleCount(1 + variant % 3); value.setFirstSeen(now.minusMinutes(30));
        value.setLastSeen(now.minusMinutes(15)); value.setCreatedAt(now); value.setUpdatedAt(now); return value;
    }
}
