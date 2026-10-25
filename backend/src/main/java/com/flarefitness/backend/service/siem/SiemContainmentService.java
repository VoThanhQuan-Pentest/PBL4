package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.exception.*;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.*;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.service.AuditLogService;
import jakarta.validation.constraints.*;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.*;

@Service
public class SiemContainmentService {
    public record Request(@NotBlank @Size(max=64) String requestId, @NotNull @Min(0) Long expectedVersion,
                          @NotBlank @Size(min=10,max=2000) String reason,
                          @NotBlank String duration) { }
    public record Release(@NotBlank @Size(max=64) String requestId, @NotNull @Min(0) Long expectedVersion,
                          @NotBlank @Size(min=10,max=2000) String reason) { }
    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS)
    public record Action(String id, String incidentId, String targetUserId, String actorUserId,
                         String reason, String durationType, LocalDateTime expiresAt, String status,
                         LocalDateTime createdAt, LocalDateTime releasedAt, long version) { }
    private final JdbcTemplate jdbc;
    private final SiemIncidentRepository incidents;
    private final UserRepository users;
    private final RedisTokenStore tokens;
    private final AuditLogService audit;
    public SiemContainmentService(JdbcTemplate jdbc, SiemIncidentRepository incidents, UserRepository users,
                                  RedisTokenStore tokens, AuditLogService audit) {
        this.jdbc=jdbc; this.incidents=incidents; this.users=users; this.tokens=tokens; this.audit=audit;
    }
    @Transactional(readOnly=true)
    public List<Action> list(String id) {
        if (!incidents.existsById(id)) throw new ResourceNotFoundException("Incident not found.");
        return query("SELECT * FROM siem_containment_actions WHERE incident_id=? ORDER BY created_at DESC LIMIT 100", id);
    }
    @Transactional
    public Action isolate(String id, Request request, Authentication authentication) {
        User actor = actor(authentication);
        validateReason(request.reason());
        Integer minutes = switch(request.duration()) {
            case "15_MINUTES" -> 15; case "1_HOUR" -> 60; case "24_HOURS" -> 1440;
            case "UNTIL_REVOKED" -> null; default -> throw new BadRequestException("Invalid isolation duration.");
        };
        // One database lock serializes idempotency, target resolution and overlapping actions.
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        List<Action> prior = query("SELECT * FROM siem_containment_actions WHERE request_id=?", request.requestId());
        if (!prior.isEmpty()) {
            Action action = prior.getFirst();
            String durationType=minutes == null ? "UNTIL_REVOKED" : "TEMPORARY";
            boolean sameDuration=action.durationType.equals(durationType) && (minutes == null
                    || Duration.between(action.createdAt,action.expiresAt).toMinutes()==minutes);
            if (!action.actorUserId.equals(actor.getId()) || !action.incidentId.equals(id)
                    || !action.reason.equals(request.reason().trim()) || !sameDuration)
                throw new ConflictException("Request ID already used for another action.");
            return action;
        }
        SiemIncident incident = assigned(id, request.expectedVersion(), actor);
        if (incident.getTargetUserId()==null) throw new BadRequestException("No verified customer target in incident.");
        User target = users.findActiveByIdForUpdate(incident.getTargetUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Customer not found."));
        if (target.getId().equals(actor.getId()) || !"ROLE_CUSTOMER".equals(CurrentUserPrincipal.toAuthority(target.getRole())))
            throw new AccessDeniedException("Only customer accounts may be isolated.");
        if (target.isSocIsolationActive()) throw new ConflictException("Customer already isolated.");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC), until=minutes==null ? null : now.plusMinutes(minutes);
        target.setSocIsolated(true); target.setSocIsolatedUntil(until);
        target.setAuthVersion((target.getAuthVersion()==null ? 0 : target.getAuthVersion()) + 1);
        users.saveAndFlush(target);
        String actionId="contain-"+UUID.randomUUID();
        jdbc.update("""
            INSERT INTO siem_containment_actions
              (id,request_id,incident_id,target_user_id,actor_user_id,reason,duration_type,expires_at,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,'APPLIED',?)
            """,actionId,request.requestId(),id,target.getId(),actor.getId(),request.reason().trim(),
                minutes==null ? "UNTIL_REVOKED" : "TEMPORARY",until,now);
        incident.setUpdatedAt(now); incidents.saveAndFlush(incident);
        history(id,actor,"ACCOUNT_ISOLATED",request.reason(),"APPLIED");
        // DB auth_version invalidates old tokens even if Redis is unavailable after commit.
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() { try { tokens.revokeAll(target.getUsername()); }
                catch (RuntimeException ignored) { /* DB version remains authoritative. */ } }
        });
        return query("SELECT * FROM siem_containment_actions WHERE id=?",actionId).getFirst();
    }
    @Transactional
    public Action release(String id, Release request, Authentication authentication) {
        User actor=actor(authentication); validateReason(request.reason());
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        Action action=query("SELECT * FROM siem_containment_actions WHERE id=?",id).stream().findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("Containment action not found."));
        List<Map<String,Object>> prior=jdbc.queryForList("SELECT * FROM siem_containment_actions WHERE release_request_id=?",request.requestId());
        if (!prior.isEmpty()) {
            Map<String,Object> row=prior.getFirst();
            if (!id.equals(row.get("id")) || !actor.getId().equals(row.get("release_actor_user_id"))
                    || !request.reason().trim().equals(row.get("release_reason")))
                throw new ConflictException("Request ID already used for another release.");
            return action;
        }
        if (action.version!=request.expectedVersion()) throw new ConflictException("Action changed; refresh first.");
        SiemIncident incident=assigned(action.incidentId,null,actor);
        if (!action.status.equals("APPLIED")) throw new ConflictException("Action already released.");
        User target=users.findActiveByIdForUpdate(action.targetUserId).orElseThrow(() -> new ResourceNotFoundException("Customer not found."));
        // An expired action cannot release a newer isolation for this customer.
        if (target.getSocIsolatedUntil()==null || Objects.equals(target.getSocIsolatedUntil(),action.expiresAt)) {
            long others=jdbc.queryForObject("SELECT COUNT(*) FROM siem_containment_actions WHERE target_user_id=? AND id<>? AND status='APPLIED' AND (expires_at IS NULL OR expires_at>?)",Long.class,target.getId(),id,LocalDateTime.now(ZoneOffset.UTC));
            if (others==0) { target.setSocIsolated(false);target.setSocIsolatedUntil(null);users.saveAndFlush(target); }
        }
        jdbc.update("UPDATE siem_containment_actions SET status='RELEASED',released_at=?,release_request_id=?,release_reason=?,release_actor_user_id=?,version=version+1 WHERE id=?",LocalDateTime.now(ZoneOffset.UTC),request.requestId(),request.reason().trim(),actor.getId(),id);
        incident.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));incidents.saveAndFlush(incident);
        history(action.incidentId,actor,"ACCOUNT_ISOLATION_RELEASED",request.reason(),"RELEASED");
        return query("SELECT * FROM siem_containment_actions WHERE id=?",id).getFirst();
    }
    public record Verification(@NotBlank @Size(max=64) String requestId,@NotNull Long expectedVersion,
            @NotBlank @Size(min=10,max=500) String reason,@NotBlank String responseResult,@NotBlank String recoveryResult) { }
    @Transactional
    public void verify(String id,Verification request,Authentication authentication) {
        User actor=actor(authentication);validateReason(request.reason());
        if(!Set.of("PASSED","NOT_REQUIRED").contains(request.responseResult()) || !Set.of("PASSED","NOT_REQUIRED").contains(request.recoveryResult()))
            throw new BadRequestException("Response and recovery checks must pass or include a reason why they are not required.");
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        String outcome=request.responseResult()+"/"+request.recoveryResult();
        var prior=jdbc.queryForList("SELECT * FROM siem_response_requests WHERE request_id=?",request.requestId());
        if(!prior.isEmpty()){
            var row=prior.getFirst();
            if(!actor.getId().equals(row.get("actor_user_id"))||!id.equals(row.get("target_id"))||!request.reason().trim().equals(row.get("reason"))||!outcome.equals(row.get("outcome")))throw new ConflictException("Request ID reused.");
            return;
        }
        SiemIncident incident=assigned(id,request.expectedVersion(),actor);
        Long pending=jdbc.queryForObject("""
            SELECT COUNT(*) FROM siem_ip_blocks b LEFT JOIN siem_prevention_policies p
              ON p.version=CASE WHEN b.revoked_at IS NULL THEN b.published_policy_version ELSE b.revoke_policy_version END
            WHERE b.incident_id=? AND (p.acknowledged_at IS NULL)
            """,Long.class,id);
        if(pending!=null && pending>0)throw new ConflictException("Gateway response still pending ACK.");
        Long failed=jdbc.queryForObject("SELECT COUNT(*) FROM siem_containment_actions WHERE incident_id=? AND status IN ('PENDING','FAILED')",Long.class,id);
        if(failed!=null && failed>0)throw new ConflictException("Containment has an unresolved action.");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        incident.setResponseVerifiedAt(now);incident.setRecoveryVerifiedAt(now);
        incident.setResponseVerificationVersion(incident.getVersion()+1);incident.setUpdatedAt(now);incidents.saveAndFlush(incident);
        jdbc.update("INSERT INTO siem_response_requests (request_id,actor_user_id,target_id,reason,outcome,created_at) VALUES (?,?,?,?,?,?)",request.requestId(),actor.getId(),id,request.reason().trim(),outcome,now);
        history(id,actor,"RESPONSE_RECOVERY_VERIFIED",outcome+": "+request.reason().trim(),outcome);
    }

    private SiemIncident assigned(String id, Long version, User actor) {
        SiemIncident i=incidents.findById(id).orElseThrow(() -> new ResourceNotFoundException("Incident not found."));
        if (version!=null && !version.equals(i.getVersion())) throw new ConflictException("Incident changed; refresh first.");
        boolean admin="ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(actor.getRole()));
        if (!admin && (i.getQueueTier()!=IncidentQueueTier.L2 || i.getStatus()!=IncidentStatus.IN_PROGRESS
                || !actor.getId().equals(i.getAssigneeUserId()))) throw new AccessDeniedException("An assigned L2 incident in progress is required.");
        return i;
    }
    private User actor(Authentication authentication) {
        if (authentication==null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal p)
                || !Set.of("ROLE_ADMIN","ROLE_SOC_L2").contains(CurrentUserPrincipal.toAuthority(p.getUser().getRole())))
            throw new AccessDeniedException("SOC L2 or Admin required.");
        return p.getUser();
    }
    private static void validateReason(String reason) {
        if(reason==null || reason.trim().length()<10 || reason.trim().length()>2000) throw new BadRequestException("A specific reason is required.");
    }
    private void history(String incident,User actor,String action,String reason,String newValue) {
        String detail=("ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(actor.getRole())) ? "ADMIN_OVERRIDE: " : "")+reason.trim();
        jdbc.update("INSERT INTO siem_incident_history (id,incident_id,actor_user_id,action,new_value,detail,ngay_tao) VALUES (?,?,?,?,?,?,?)",
                "siem-history-"+UUID.randomUUID(),incident,actor.getId(),action,newValue,detail,LocalDateTime.now(ZoneOffset.UTC));
        audit.success(action,actor.getId(),null,"SIEM_INCIDENT",incident);
    }
    private List<Action> query(String sql,Object... args) {
        return jdbc.query(sql,(r,n)->new Action(r.getString("id"),r.getString("incident_id"),r.getString("target_user_id"),
                r.getString("actor_user_id"),r.getString("reason"),r.getString("duration_type"),
                r.getObject("expires_at",LocalDateTime.class),r.getString("status"),r.getObject("created_at",LocalDateTime.class),
                r.getObject("released_at",LocalDateTime.class),r.getLong("version")),args);
    }
}
