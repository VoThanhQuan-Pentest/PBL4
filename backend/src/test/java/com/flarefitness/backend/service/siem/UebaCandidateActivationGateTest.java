package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemUebaModelJob;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class UebaCandidateActivationGateTest {
    private final SiemUebaGateway worker = mock(SiemUebaGateway.class);
    private final SiemUebaModelJobRepository jobs = mock(SiemUebaModelJobRepository.class);
    private final UebaExperimentCatalog catalog = mock(UebaExperimentCatalog.class);
    private final SiemUebaModelService service = new SiemUebaModelService(worker,
            mock(SiemAccountBehaviorWindowRepository.class), jobs, mock(SiemSecurityEventRepository.class),
            mock(AuditLogService.class), catalog, new ObjectMapper());

    @ParameterizedTest
    @ValueSource(strings = {"SOC L1", "SOC L2", "CUSTOMER", "STAFF"})
    void nonAdminCannotReachRecipesEvaluationOrActivation(String role) {
        assertThatThrownBy(() -> service.recipes(actor(role))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> service.evaluate("model-test-1234", new SiemDtos.EvaluateUebaModel("dataset-valid-1234"), actor(role)))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> service.activate("model-test-1234", actor(role))).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(worker, jobs, catalog);
    }

    @ParameterizedTest
    @ValueSource(strings = {"NOT_RUN", "FAIL", "PASS", "LEGACY_RESTORE"})
    void fittingSuccessOrBarePassDoesNotAuthorizeNewActivation(String gate) {
        SiemUebaModelJob job = new SiemUebaModelJob();
        job.setModelVersion("model-test-1234"); job.setStatus("SUCCEEDED"); job.setQualityGate(gate);
        job.setEvaluationStatus("NOT_RUN"); job.setFeatureSchemaVersion(2);
        when(jobs.lockedByModelVersion(job.getModelVersion())).thenReturn(Optional.of(job));
        assertThatThrownBy(() -> service.activate(job.getModelVersion(), actor("ADMIN"))).isInstanceOf(ConflictException.class);
        verifyNoInteractions(worker, catalog);
    }

    @ParameterizedTest
    @ValueSource(strings = {"QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "INTERRUPTED"})
    void frozenOrExistingEvaluationCannotBeSubmittedAgain(String state) {
        var job = new SiemUebaModelJob();
        job.setModelVersion("model-test-1234"); job.setEvaluationStatus(state);
        when(jobs.lockedByModelVersion(job.getModelVersion())).thenReturn(Optional.of(job));
        assertThatThrownBy(() -> service.evaluate(job.getModelVersion(), new SiemDtos.EvaluateUebaModel("dataset-valid-1234"), actor("ADMIN")))
                .isInstanceOf(ConflictException.class);
        verifyNoInteractions(worker, catalog);
    }

    private static UsernamePasswordAuthenticationToken actor(String role) {
        User user = new User(); user.setId("operator-owned-test"); user.setRole(role); user.setStatus("Hoat dong"); user.setDeleted(false);
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
