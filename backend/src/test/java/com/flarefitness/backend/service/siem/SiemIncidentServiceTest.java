package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.siem.SiemAlertRefRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentNoteRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemTestWindowRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.access.AccessDeniedException;

@ExtendWith(MockitoExtension.class)
class SiemIncidentServiceTest {
    @Mock private SiemIncidentRepository incidents;
    @Mock private SiemAlertRefRepository alerts;
    @Mock private SiemIncidentNoteRepository notes;
    @Mock private SiemIncidentHistoryRepository history;
    @Mock private SiemTestWindowRepository windows;
    @Mock private UserRepository users;
    private SiemIncidentService service;

    @BeforeEach
    void setUp() {
        service = new SiemIncidentService(incidents, alerts, notes, history, windows, users);
    }

    @Test
    void requestedStaffProjectionIsBatchedAndUsesActualRoleWhileLegacyPayloadStaysUnchanged() throws Exception {
        var value = incident(); value.setAssigneeUserId("analyst-1"); value.setQueueTier(IncidentQueueTier.L2);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(value));
        var original = service.incidentProjection("inc-1");
        org.mockito.Mockito.verifyNoInteractions(users);
        var staff = org.mockito.Mockito.mock(UserRepository.AnalystIdentity.class);
        when(staff.getId()).thenReturn("analyst-1"); when(staff.getName()).thenReturn("James"); when(staff.getRole()).thenReturn("Security analyst");
        when(users.findAnalystIdentities(java.util.List.of("analyst-1"))).thenReturn(java.util.List.of(staff));
        var page = new com.flarefitness.backend.dto.common.PageResponse<>(java.util.List.of(original, original), 0, 50, 2, 1, false);
        var enriched = service.includeAssignedAnalysts(page);
        assertThat(enriched.content()).allSatisfy(item -> {
            assertThat(item.assignedAnalyst()).isEqualTo(new SiemDtos.AssignedAnalyst("James", "SOC_L1"));
            assertThat(item.queueTier()).isEqualTo(IncidentQueueTier.L2);
        });
        org.mockito.Mockito.verify(users, org.mockito.Mockito.times(1)).findAnalystIdentities(java.util.List.of("analyst-1"));
        var json = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
                .setPropertyNamingStrategy(com.fasterxml.jackson.databind.PropertyNamingStrategies.SNAKE_CASE);
        assertThat(json.valueToTree(original).has("assigned_analyst")).isFalse();
        var identity = json.valueToTree(enriched.content().getFirst()).path("assigned_analyst");
        assertThat(identity.size()).isEqualTo(2); assertThat(identity.path("name").asText()).isEqualTo("James");
        assertThat(identity.path("role").asText()).isEqualTo("SOC_L1");
    }

    @Test
    void unassignedCaseDoesNotFetchOrInventAStaffIdentity() {
        var value = incident(); value.setAssigneeUserId(null);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(value));
        var detail = new SiemDtos.IncidentDetail(service.incidentProjection("inc-1"), java.util.List.of());
        assertThat(service.includeAssignedAnalyst(detail).incident().assignedAnalyst()).isNull();
        var page=new com.flarefitness.backend.dto.common.PageResponse<>(java.util.List.of(detail.incident()),0,50,1,1,false);
        assertThat(service.includeAssignedAnalysts(page).content().getFirst().assignedAnalyst()).isNull();
        org.mockito.Mockito.verifyNoInteractions(users);
    }

    @Test
    void rejectsStaleAndCompetingClaims() {
        SiemIncident incident = incident();
        incident.setAssigneeUserId("other-analyst");
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));

        assertThatThrownBy(() -> service.updateIncident("inc-1",
                new SiemDtos.UpdateIncident(0L, IncidentStatus.IN_PROGRESS, null, null, null), auth()))
                .isInstanceOf(ConflictException.class);
        assertThatThrownBy(() -> service.updateIncident("inc-1",
                new SiemDtos.UpdateIncident(1L, IncidentStatus.IN_PROGRESS, null, null, null), auth()))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("analyst khac");
    }

    @Test
    void closingRequiresConclusionAndNote() {
        SiemIncident incident = incident();
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));

        assertThatThrownBy(() -> service.updateIncident("inc-1",
                new SiemDtos.UpdateIncident(1L, IncidentStatus.CLOSED,
                        IncidentConclusion.UNREVIEWED, "checked", null), auth()))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.updateIncident("inc-1",
                new SiemDtos.UpdateIncident(1L, IncidentStatus.CLOSED,
                        IncidentConclusion.TRUE_POSITIVE, " ", null), auth()))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void reopeningMovesClosedIncidentToInProgressAndClearsConclusion() {
        SiemIncident incident = incident();
        incident.setStatus(IncidentStatus.CLOSED);
        incident.setConclusion(IncidentConclusion.TRUE_POSITIVE);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        when(incidents.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        SiemDtos.Incident result = service.updateIncident("inc-1",
                new SiemDtos.UpdateIncident(1L, IncidentStatus.IN_PROGRESS,
                        IncidentConclusion.UNREVIEWED, "New evidence", true), auth());

        assertThat(result.status()).isEqualTo(IncidentStatus.IN_PROGRESS);
        assertThat(result.conclusion()).isEqualTo(IncidentConclusion.UNREVIEWED);
        assertThat(result.assigneeUserId()).isEqualTo("analyst-1");
    }

    @Test
    void l1EscalationReleasesIncidentIntoL2Queue() {
        SiemIncident incident = incident();
        incident.setStatus(IncidentStatus.IN_PROGRESS);
        incident.setAssigneeUserId("analyst-1");
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        when(incidents.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        SiemDtos.Incident result = service.transitionIncident("inc-1",
                new SiemDtos.TransitionIncident(1L, SiemDtos.TransitionAction.ESCALATE,
                        "Multiple independent signals", null), auth());

        assertThat(result.queueTier()).isEqualTo(IncidentQueueTier.L2);
        assertThat(result.status()).isEqualTo(IncidentStatus.NEW);
        assertThat(result.assigneeUserId()).isNull();
    }

    @Test
    void l1CannotClaimL2OrCloseHighIncident() {
        SiemIncident incident = incident();
        incident.setQueueTier(IncidentQueueTier.L2);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        assertThatThrownBy(() -> service.transitionIncident("inc-1",
                new SiemDtos.TransitionIncident(1L, SiemDtos.TransitionAction.CLAIM, null, null), auth()))
                .isInstanceOf(AccessDeniedException.class);

        incident.setQueueTier(IncidentQueueTier.L1);
        incident.setStatus(IncidentStatus.IN_PROGRESS);
        incident.setAssigneeUserId("analyst-1");
        assertThatThrownBy(() -> service.transitionIncident("inc-1",
                new SiemDtos.TransitionIncident(1L, SiemDtos.TransitionAction.CLOSE,
                        "Confirmed account takeover", IncidentConclusion.TRUE_POSITIVE), auth()))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void l2CanConcludeClaimedHighIncident() {
        SiemIncident incident = incident();
        incident.setQueueTier(IncidentQueueTier.L2);
        incident.setStatus(IncidentStatus.IN_PROGRESS);
        incident.setAssigneeUserId("analyst-1");
        incident.setResponseVerifiedAt(LocalDateTime.now());incident.setRecoveryVerifiedAt(LocalDateTime.now());incident.setResponseVerificationVersion(1L);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        when(incidents.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        SiemDtos.Incident result = service.transitionIncident("inc-1",
                new SiemDtos.TransitionIncident(1L, SiemDtos.TransitionAction.CLOSE,
                        "Confirmed by timeline review", IncidentConclusion.TRUE_POSITIVE), auth("SOC L2"));

        assertThat(result.status()).isEqualTo(IncidentStatus.CLOSED);
        assertThat(result.conclusion()).isEqualTo(IncidentConclusion.TRUE_POSITIVE);
    }

    @Test
    void confirmedClosureRequiresCurrentResponseAndRecoveryVerification() {
        SiemIncident incident=incident();incident.setQueueTier(IncidentQueueTier.L2);incident.setStatus(IncidentStatus.IN_PROGRESS);incident.setAssigneeUserId("analyst-1");
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        var request=new SiemDtos.TransitionIncident(1L,SiemDtos.TransitionAction.CLOSE,"Confirmed after response checks",IncidentConclusion.TRUE_POSITIVE);
        assertThatThrownBy(()->service.transitionIncident("inc-1",request,auth("SOC L2"))).isInstanceOf(com.flarefitness.backend.exception.ConflictException.class);
        incident.setResponseVerifiedAt(LocalDateTime.now());incident.setRecoveryVerifiedAt(LocalDateTime.now());incident.setResponseVerificationVersion(0L);
        assertThatThrownBy(()->service.transitionIncident("inc-1",request,auth("SOC L2"))).isInstanceOf(com.flarefitness.backend.exception.ConflictException.class);
    }

    @Test
    void dashboardRejectsAnyRangeLongerThanExactlySevenDays() {
        LocalDateTime to = LocalDateTime.of(2035, 1, 8, 12, 0);

        assertThatThrownBy(() -> service.dashboardSummary(to.minusDays(7).minusSeconds(1), to))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("7 ngay");
    }

    private SiemIncident incident() {
        LocalDateTime now = LocalDateTime.now();
        SiemIncident value = new SiemIncident();
        value.setId("inc-1");
        value.setTitle("Repeated login failures");
        value.setGroupingKey("group-1");
        value.setBucketStart(now);
        value.setSourceSeverity("high");
        value.setScore(70);
        value.setSeverity(IncidentSeverity.HIGH);
        value.setClassification(IncidentClassification.INVESTIGATE);
        value.setClassificationReason("test");
        value.setMissingData(false);
        value.setStatus(IncidentStatus.NEW);
        value.setConclusion(IncidentConclusion.UNREVIEWED);
        value.setManualInvestigateOverride(false);
        value.setAlertCount(1);
        value.setDistinctRuleCount(1);
        value.setFirstSeen(now);
        value.setLastSeen(now);
        value.setUpdatedAt(now);
        value.setVersion(1L);
        return value;
    }

    private UsernamePasswordAuthenticationToken auth() {
        return auth("Security analyst");
    }

    private UsernamePasswordAuthenticationToken auth(String role) {
        User user = new User();
        user.setId("analyst-1");
        user.setUsername("analyst");
        user.setPassword("not-used");
        user.setRole(role);
        user.setStatus("Hoat dong");
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
