package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import com.flarefitness.backend.entity.siem.SiemResponseAction;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemResponseActionRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.service.AuditLogService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class SiemResponseActionService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SiemResponseActionService.class);
    private final SiemIncidentRepository incidentRepository;
    private final SiemResponseActionRepository actionRepository;
    private final SiemIncidentHistoryRepository historyRepository;
    private final UserRepository userRepository;
    private final RedisTokenStore tokenStore;
    private final AuditLogService auditLogService;

    public SiemResponseActionService(SiemIncidentRepository incidentRepository,
                                     SiemResponseActionRepository actionRepository,
                                     SiemIncidentHistoryRepository historyRepository,
                                     UserRepository userRepository, RedisTokenStore tokenStore,
                                     AuditLogService auditLogService) {
        this.incidentRepository = incidentRepository;
        this.actionRepository = actionRepository;
        this.historyRepository = historyRepository;
        this.userRepository = userRepository;
        this.tokenStore = tokenStore;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public SiemDtos.SessionRevocationResult revokeCustomerSessions(
            String incidentId, SiemDtos.RevokeSessions request, Authentication authentication) {
        if (!(authentication != null && authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new AccessDeniedException("Chi SOC L2 duoc xu ly phien khach hang.");
        }
        User actor = principal.getUser();
        String authority = CurrentUserPrincipal.toAuthority(actor.getRole());
        if (!"ROLE_SOC_L2".equals(authority) && !"ROLE_ADMIN".equals(authority)) {
            throw new AccessDeniedException("Chi SOC L2 duoc thu hoi phien khach hang.");
        }
        SiemResponseAction prior = actionRepository.findByRequestId(request.requestId()).orElse(null);
        if (prior != null) {
            if (!prior.getActorUserId().equals(actor.getId())
                    || !prior.getIncidentId().equals(incidentId)
                    || !prior.getReason().equals(request.reason().trim())) {
                throw new ConflictException("Request ID da duoc dung cho thao tac khac.");
            }
            return toResponse(prior);
        }

        SiemIncident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay incident."));
        if (!incident.getVersion().equals(request.expectedVersion())) {
            throw new ConflictException("Incident da thay doi. Hay tai lai truoc khi xu ly.");
        }
        if (incident.getQueueTier() != IncidentQueueTier.L2
                || incident.getStatus() != IncidentStatus.IN_PROGRESS
                || !actor.getId().equals(incident.getAssigneeUserId())
                || incident.getOrigin() != IncidentOrigin.UEBA
                || incident.getTargetUserId() == null) {
            throw new AccessDeniedException("Incident khong du dieu kien thu hoi phien.");
        }
        User target = userRepository.findActiveByIdForUpdate(incident.getTargetUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay tai khoan khach hang."));
        if (!"ROLE_CUSTOMER".equals(CurrentUserPrincipal.toAuthority(target.getRole()))) {
            throw new AccessDeniedException("Chi duoc thu hoi phien tai khoan khach hang.");
        }

        long previousVersion = target.getAuthVersion() == null ? 0L : target.getAuthVersion();
        long nextVersion = previousVersion + 1;
        target.setAuthVersion(nextVersion);
        userRepository.saveAndFlush(target);
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemResponseAction action = new SiemResponseAction();
        action.setId("siem-action-" + UUID.randomUUID());
        action.setRequestId(request.requestId());
        action.setIncidentId(incidentId);
        action.setTargetUserId(target.getId());
        action.setActorUserId(actor.getId());
        action.setActionType("REVOKE_SESSIONS");
        action.setReason(request.reason().trim());
        action.setPreviousAuthVersion(previousVersion);
        action.setNewAuthVersion(nextVersion);
        action.setCreatedAt(now);
        try {
            actionRepository.saveAndFlush(action);
        } catch (DataIntegrityViolationException duplicate) {
            throw new ConflictException("Request ID da duoc xu ly boi phien khac.");
        }

        SiemIncidentHistory history = new SiemIncidentHistory();
        history.setId("siem-history-" + UUID.randomUUID());
        history.setIncidentId(incidentId);
        history.setActorUserId(actor.getId());
        history.setAction("CUSTOMER_SESSIONS_REVOKED");
        history.setPreviousValue(Long.toString(previousVersion));
        history.setNewValue(Long.toString(nextVersion));
        history.setDetail(request.reason().trim());
        history.setCreatedAt(now);
        historyRepository.save(history);
        auditLogService.success("SOC_CUSTOMER_SESSIONS_REVOKED", actor.getId(), target.getId(),
                "SIEM_INCIDENT", incidentId);

        String username = target.getUsername();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    tokenStore.revokeAll(username);
                } catch (RuntimeException exception) {
                    LOGGER.warn("Redis session cleanup failed for customerId={} exceptionType={}",
                            target.getId(), exception.getClass().getSimpleName());
                }
            }
        });
        return toResponse(action);
    }

    private SiemDtos.SessionRevocationResult toResponse(SiemResponseAction action) {
        return new SiemDtos.SessionRevocationResult(action.getId(), action.getIncidentId(),
                action.getTargetUserId(), action.getActorUserId(), action.getNewAuthVersion(),
                action.getCreatedAt(), true);
    }
}
