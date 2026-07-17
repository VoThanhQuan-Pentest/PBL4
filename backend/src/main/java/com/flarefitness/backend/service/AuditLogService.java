package com.flarefitness.backend.service;

import com.flarefitness.backend.security.CurrentUserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Emits a deliberately small, structured audit trail for sensitive operations.
 *
 * <p>Only opaque identifiers are accepted. Callers must never pass credentials,
 * OTPs, tokens, email addresses, phone numbers, names, addresses, or request
 * payloads. Successful events are emitted after the surrounding transaction
 * commits so a rolled-back operation is not reported as successful.</p>
 */
@Component
public class AuditLogService {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("AUDIT");
    private static final String UNKNOWN_ACTOR = "SYSTEM";

    public void success(
            String action,
            String actorId,
            String subjectId,
            String resourceType,
            String resourceId
    ) {
        AuditEvent event = new AuditEvent(
                action,
                "SUCCESS",
                actorId,
                subjectId,
                resourceType,
                resourceId,
                MDC.get("traceId"));
        if (TransactionSynchronizationManager.isSynchronizationActive()
                && TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    emit(event);
                }
            });
            return;
        }
        emit(event);
    }

    /** Failure events are emitted immediately because their transaction normally rolls back. */
    public void failure(String action, String actorId, String subjectId, String resourceType, String resourceId) {
        emit(new AuditEvent(
                action,
                "FAILURE",
                actorId,
                subjectId,
                resourceType,
                resourceId,
                MDC.get("traceId")));
    }

    /** Returns the authenticated opaque account id, or SYSTEM when no user is authenticated. */
    public String currentActorId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof CurrentUserPrincipal principal
                && principal.getUser() != null && !isBlank(principal.getUser().getId())) {
            return principal.getUser().getId();
        }
        return UNKNOWN_ACTOR;
    }

    private void emit(AuditEvent event) {
        AUDIT_LOG.info(
                "action={} outcome={} actorId={} subjectId={} resourceType={} resourceId={} traceId={}",
                safe(event.action()),
                safe(event.outcome()),
                safe(event.actorId()),
                safe(event.subjectId()),
                safe(event.resourceType()),
                safe(event.resourceId()),
                safe(event.traceId()));
    }

    private String safe(String value) {
        if (isBlank(value)) {
            return "-";
        }
        StringBuilder result = new StringBuilder(Math.min(value.length(), 128));
        for (int index = 0; index < value.length() && result.length() < 128; index++) {
            char character = value.charAt(index);
            if (Character.isLetterOrDigit(character)
                    || character == '-' || character == '_' || character == '.' || character == ':') {
                result.append(character);
            } else {
                result.append('_');
            }
        }
        return result.toString();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private record AuditEvent(
            String action,
            String outcome,
            String actorId,
            String subjectId,
            String resourceType,
            String resourceId,
            String traceId
    ) {
    }
}
