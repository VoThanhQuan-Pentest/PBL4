package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.SensitiveActionConfirmation;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.*;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import com.flarefitness.backend.service.SensitiveActionPolicy;
import com.flarefitness.backend.service.SensitiveActionConfirmationService.Actor;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Independent PROJECT_LIMITED guard. A model response never authorizes a write or bypasses OTP. */
@Service
public class PostloginDecisionService {
    public record Policy(String mode, Set<String> accounts, String manifest, long version) { }
    public record Ticket(String id, String holdKey, String mode, long policyVersion, LocalDateTime asOf) { }
    private record Hold(String decisionId, LocalDateTime expires, LocalDateTime released) {
        boolean active(LocalDateTime at) { return released == null && expires.isAfter(at); }
    }
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final UserRepository users;
    private final SensitiveActionConfirmationRepository actions;
    private final SensitiveActionPolicy otpPolicy;
    private final PostloginSnapshotService snapshots;
    private final SiemUebaGateway gateway;
    private final AuditLogService audit;
    private final TransactionTemplate independent;
    private final boolean enabled;
    private final String expectedManifest;
    private final Path holdFile;
    private final Clock clock;

    @Autowired
    public PostloginDecisionService(JdbcTemplate jdbc, ObjectMapper json, UserRepository users,
            SensitiveActionConfirmationRepository actions, SensitiveActionPolicy otpPolicy,
            PostloginSnapshotService snapshots, SiemUebaGateway gateway, AuditLogService audit,
            PlatformTransactionManager tx,
            @Value("${siem.postlogin.enabled:false}") boolean enabled,
            @Value("${siem.postlogin.manifest-sha256:}") String expectedManifest,
            @Value("${siem.postlogin.operator-hold-file:/run/ueba-postlogin/operator-hold.json}") String holdFile) {
        this(jdbc, json, users, actions, otpPolicy, snapshots, gateway, audit, tx, enabled, expectedManifest, holdFile, Clock.systemUTC());
    }

    PostloginDecisionService(JdbcTemplate jdbc, ObjectMapper json, UserRepository users,
            SensitiveActionConfirmationRepository actions, SensitiveActionPolicy otpPolicy,
            PostloginSnapshotService snapshots, SiemUebaGateway gateway, AuditLogService audit,
            PlatformTransactionManager tx, boolean enabled, String expectedManifest, String holdFile, Clock clock) {
        this.jdbc=jdbc; this.json=json; this.users=users; this.actions=actions; this.otpPolicy=otpPolicy;
        this.snapshots=snapshots; this.gateway=gateway; this.audit=audit; this.enabled=enabled;
        this.expectedManifest=expectedManifest; this.holdFile=Path.of(holdFile); this.clock=clock;
        this.independent=new TransactionTemplate(tx);
        independent.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        independent.setTimeout(5);
    }

    public Policy policy() { return readPolicy(false); }

    private Policy readPolicy(boolean lock) {
        if (!enabled) return new Policy("OFF", Set.of(), "", 0);
        return jdbc.queryForObject("SELECT * FROM siem_postlogin_policy WHERE id=?" + (lock ? " FOR UPDATE" : ""),
                (row,n) -> {
                    try {
                        var list=json.readTree(row.getString("account_allowlist_json"));
                        Set<String> accounts=new HashSet<>();
                        if (!list.isArray() || list.size()>3) throw new IllegalArgumentException();
                        for (var id:list) {
                            if (!id.isTextual() || !id.asText().matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException();
                            accounts.add(id.asText());
                        }
                        String mode=row.getString("mode");
                        if (!Set.of("OFF","OBSERVE","ENFORCE_LIMITED").contains(mode)
                                || !PostloginDecisionPolicy.MODEL.equals(row.getString("model_version"))) throw new IllegalArgumentException();
                        if ("ENFORCE_LIMITED".equals(mode) && (operatorHeld()
                                || !expectedManifest.matches("[a-f0-9]{64}")
                                || !expectedManifest.equals(row.getString("model_manifest_sha256")))) mode="OBSERVE";
                        return new Policy(mode, Set.copyOf(accounts), row.getString("model_manifest_sha256"), row.getLong("version"));
                    } catch (Exception invalid) { throw new ServiceUnavailableException("Chinh sach bao ve chua san sang."); }
                }, PostloginDecisionPolicy.ID);
    }

    public boolean operatorHeld() {
        try {
            if (!Files.isRegularFile(holdFile, LinkOption.NOFOLLOW_LINKS) || Files.size(holdFile)>2048) return true;
            var value=json.readTree(Files.readAllBytes(holdFile));
            return !value.path("hold_new_units").isBoolean() || value.path("hold_new_units").asBoolean();
        } catch (Exception unavailable) { return true; }
    }

    private boolean applies(Policy p, User user) {
        return !"OFF".equals(p.mode()) && p.accounts().contains(user.getId()) && otpPolicy.requiresConfirmation(user)
                && "ROLE_CUSTOMER".equals(CurrentUserPrincipal.toAuthority(user.getRole()));
    }

    /** Avoid sending another OTP while an existing operation hold is active. */
    public void beforePrepare(Actor actor, String operation) {
        if (!enabled || actor == null || actor.session() == null) return;
        var p=policy(); var user=users.findActiveById(actor.userId()).orElse(null);
        if (user == null || !applies(p,user) || !"ENFORCE_LIMITED".equals(p.mode())) return;
        var h=findHold(key(actor,operation),false);
        if (h != null && h.active(now())) throw held(h);
    }

    /** Own transaction makes denial/audit durable even when the subsequent business transaction rolls back. */
    public Ticket beforeExecute(Actor actor, String challengeId, String requestId, String sourceIp) {
        if (!enabled) return null;
        var p=policy();
        var user=users.findActiveById(actor.userId()).orElseThrow(() -> new ResourceNotFoundException("Tai khoan khong con hieu luc."));
        if (!applies(p,user)) return null;
        var action=actions.findById(challengeId).orElseThrow(() -> new ResourceNotFoundException("Khong tim thay yeu cau."));
        requireBound(actor,user,action);
        if ("COMMITTED".equals(action.getState())) return null; // Existing challenge idempotency remains authoritative.
        if (!"PENDING".equals(action.getState()) || !action.getExpiresAt().isAfter(now())) throw stale(null);
        if (requestId == null && "OBSERVE".equals(p.mode())) requestId=UUID.randomUUID().toString();
        if (requestId == null || !requestId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
            throw new PostloginActionException(PostloginActionException.Kind.REQUEST_ID_REQUIRED,
                    "Hay tai lai trang de cap nhat yeu cau xac nhan.",null,null);
        }
        String requestKey=requestId, holdKey=key(actor,action.getOperation());
        Hold current=findHold(holdKey,false);
        if ("ENFORCE_LIMITED".equals(p.mode()) && current!=null && current.active(now())) throw held(current);
        var existing=findRequest(actor,challengeId,requestKey);
        if (existing != null) throw prior(existing);
        LocalDateTime at=now();
        PostloginSnapshotService.Snapshot snapshot;
        try { snapshot=snapshots.build(actor,action,sourceIp,at); }
        catch (IllegalArgumentException | IllegalStateException invalid) { snapshot=new PostloginSnapshotService.Snapshot(Map.of(),false,false,0,0,0,false); }
        SiemUebaGateway.PostloginScore score=null;
        if (snapshot.covered()) {
            try { score=gateway.scorePostlogin(snapshot.packet(),expectedManifest); }
            catch (ServiceUnavailableException unavailable) { /* An unavailable model cannot create a hold. */ }
        }
        var frozen=snapshot; var model=score;
        Ticket ticket=independent.execute(tx -> {
            Policy locked=readPolicy(true);
            if (locked.version()!=p.version() || !locked.mode().equals(p.mode()) || !applies(locked,user)) throw stale(null);
            Hold h=lockHold(holdKey,actor,action.getOperation(),p,at);
            // Concurrent same-request writers serialize on the operation hold row.
            if (findRequest(actor,challengeId,requestKey)!=null) throw prior(findRequest(actor,challengeId,requestKey));
            if ("ENFORCE_LIMITED".equals(p.mode()) && h.active(at)) {
                return new Ticket(h.decisionId(),holdKey,p.mode(),p.version(),at);
            }
            int failures=failures(actor,action.getOperation(),p,at);
            boolean abuse=freshHighAbuse(sourceIp,at);
            var result=PostloginDecisionPolicy.assess(new PostloginDecisionPolicy.Input(frozen.covered(),frozen.ready(),frozen.trusted(),
                    model!=null,model!=null&&model.aboveThreshold(),model==null?null:model.context(),
                    frozen.requests(),frozen.serverErrors(),failures,frozen.sameSourceScan(),abuse));
            String id="pld-"+UUID.randomUUID();
            boolean deny="ENFORCE_LIMITED".equals(p.mode()) && (h.active(at)
                    || result.decision()==PostloginDecisionPolicy.Decision.TEMP_HOLD && !releasedGrace(h,at));
            if (deny && !h.active(at)) {
                h=startHold(holdKey,id,at,p.version()); audit.success("POSTLOGIN_TEMP_HOLD",actor.userId(),actor.userId(),"DECISION",id);
            }
            List<String> reasons=new ArrayList<>(result.reasons());
            if (deny) reasons.add("ACTIVE_SESSION_OPERATION_HOLD");
            if (releasedGrace(h,at)) reasons.add("ANALYST_RELEASE_KEEP_OTP");
            Map<String,Object> evidence=Map.of("same_source_scan",frozen.sameSourceScan(),
                    "real_fresh_abuse",abuse,"otp_failures",failures,"capture_stage","PRE_EXECUTION",
                    "provider_cache",providerEvidence(sourceIp));
            jdbc.update("""
                    INSERT INTO siem_postlogin_decisions
                    (id,request_id,challenge_id,user_id,session_pseudonym,auth_version,operation,snapshot_id,mode,decision,
                    context_class,raw_score,normal_percentile,model_version,model_sha256,model_manifest_sha256,policy_id,policy_version,
                    reasons_json,ip_evidence_json,feature_snapshot_json,baseline_established,trusted_window_count,hold_key,hold_expires_at,
                    outcome,as_of,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,id,requestKey,challengeId,actor.userId(),actor.session().sessionPseudonym(),actor.authVersion(),action.getOperation(),
                    frozen.covered()?frozen.packet().get("snapshot_id"):"uncovered-"+UUID.randomUUID(),p.mode(),
                    deny?"TEMP_HOLD":result.decision().name(),model==null?null:model.context(),model==null?null:model.rawScore(),
                    model==null?null:model.normalPercentile(),PostloginDecisionPolicy.MODEL,model==null?null:model.modelSha256(),
                    model==null?null:model.manifestSha256(),PostloginDecisionPolicy.ID,p.version(),write(reasons),write(evidence),
                    write(frozen.packet()),frozen.ready(),frozen.trusted(),holdKey,deny?h.expires():null,deny?"HELD":"PENDING",at,at,at);
            String execution=SecurityEventService.executionReference(actor.userId(),action.getOperation(),actor.session().sessionPseudonym());
            if(execution!=null)jdbc.update("UPDATE siem_postlogin_decisions SET execution_event_id=? WHERE id=?",execution,id);
            audit.success("POSTLOGIN_DECISION",actor.userId(),actor.userId(),"DECISION",id);
            return new Ticket(id,holdKey,p.mode(),p.version(),at);
        });
        Hold after=findHold(holdKey,false);
        if ("ENFORCE_LIMITED".equals(ticket.mode()) && after!=null && after.active(now())) throw held(after);
        return ticket;
    }

    /** Caller already locks account then challenge. All guard writers lock policy -> hold -> decision. */
    public void enforceInsideTransaction(Ticket t, Actor actor, SensitiveActionConfirmation action) {
        if (t==null) return;
        var p=readPolicy(true);
        if (p.version()!=t.policyVersion() || !p.mode().equals(t.mode())) throw stale(t.id());
        Hold h=findHold(t.holdKey(),true);
        var row=jdbc.queryForMap("SELECT * FROM siem_postlogin_decisions WHERE id=? FOR UPDATE",t.id());
        if (!actor.userId().equals(row.get("user_id")) || !action.getId().equals(row.get("challenge_id"))
                || !actor.session().sessionPseudonym().equals(row.get("session_pseudonym"))
                || actor.authVersion()!=((Number)row.get("auth_version")).longValue()
                || !action.getOperation().equals(row.get("operation")) || !"PENDING".equals(row.get("outcome"))
                || now().isAfter(t.asOf().plusSeconds(5))) throw stale(t.id());
        if ("ENFORCE_LIMITED".equals(p.mode()) && h!=null && h.active(now())) throw held(h);
    }

    /** Atomic with the customer mutation; no independent transaction here. */
    public void committed(Ticket t) {
        if (t!=null && jdbc.update("UPDATE siem_postlogin_decisions SET outcome='COMMITTED',updated_at=?,version=version+1 WHERE id=? AND outcome='PENDING'",
                now(),t.id())!=1) throw stale(t.id());
    }

    public void replayedCommitted(Ticket t) {
        if (t!=null && jdbc.update("UPDATE siem_postlogin_decisions SET outcome='REPLAY_COMMITTED',updated_at=?,version=version+1 WHERE id=? AND outcome='PENDING'",
                now(),t.id())!=1) throw stale(t.id());
    }

    /** Called only AFTER business rollback. Count exactly one invalid confirmation per unique request. */
    public void failed(Ticket t, Actor actor, String operation, boolean invalidOtp) {
        if (t==null) return;
        Hold h=independent.execute(tx -> {
            var p=readPolicy(true); Hold locked=findHold(t.holdKey(),true);
            var row=jdbc.queryForMap("SELECT * FROM siem_postlogin_decisions WHERE id=? FOR UPDATE",t.id());
            if (!"PENDING".equals(row.get("outcome"))) return locked;
            var at=now();
            jdbc.update("UPDATE siem_postlogin_decisions SET outcome=?,updated_at=?,version=version+1 WHERE id=?",
                    invalidOtp?"OTP_REJECTED":"BUSINESS_REJECTED",at,t.id());
            if (p.version()!=t.policyVersion() || !p.mode().equals(t.mode())) return null;
            if (!invalidOtp) return locked;
            boolean eligible=Boolean.TRUE.equals(row.get("baseline_established"))
                    || row.get("baseline_established") instanceof Number n && n.intValue()==1;
            double percentile=row.get("normal_percentile") instanceof Number n?n.doubleValue():0;
            if (eligible && ((Number)row.get("trusted_window_count")).intValue()>=30 && percentile>=99.99
                    && "BEHAVIOR_REVIEW_CONTEXT".equals(row.get("context_class"))
                    && failures(actor,operation,p,at)>=3) {
                boolean enforce="ENFORCE_LIMITED".equals(p.mode()) && !releasedGrace(locked,at);
                if (enforce && !locked.active(at)) locked=startHold(t.holdKey(),t.id(),at,p.version());
                jdbc.update("UPDATE siem_postlogin_decisions SET decision='TEMP_HOLD',hold_expires_at=?,reasons_json=?,version=version+1 WHERE id=?",
                        enforce?locked.expires():null,write(List.of("MODEL_HIGH_AND_THREE_SESSION_OTP_FAILURES")),t.id());
                if (enforce) audit.success("POSTLOGIN_TEMP_HOLD",actor.userId(),actor.userId(),"DECISION",t.id());
            }
            return locked;
        });
        if ("ENFORCE_LIMITED".equals(t.mode()) && h!=null && h.active(now())) throw held(h);
    }

    private int failures(Actor a,String operation,Policy p,LocalDateTime at) {
        return jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_postlogin_decisions d WHERE user_id=? AND session_pseudonym=? AND operation=?
                AND policy_id=? AND policy_version=? AND mode=? AND outcome='OTP_REJECTED' AND created_at>=?
                AND created_at>COALESCE((SELECT MAX(s.updated_at) FROM siem_postlogin_decisions s
                WHERE s.user_id=d.user_id AND s.session_pseudonym=d.session_pseudonym AND s.operation=d.operation
                AND s.policy_id=d.policy_id AND s.policy_version=d.policy_version AND s.mode=d.mode AND s.outcome='COMMITTED'),'1970-01-01')
                AND created_at>COALESCE((SELECT MAX(h.starts_at) FROM siem_postlogin_holds h WHERE h.user_id=d.user_id
                AND h.session_pseudonym=d.session_pseudonym AND h.operation=d.operation AND h.policy_id=d.policy_id
                AND h.decision_id<>'NONE'),'1970-01-01')
                """,Integer.class,a.userId(),a.session().sessionPseudonym(),operation,PostloginDecisionPolicy.ID,p.version(),p.mode(),at.minusMinutes(15));
    }

    private boolean freshHighAbuse(String ip,LocalDateTime at) {
        if (ip==null) return false;
        return jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_intelligence WHERE ip_address=? AND provider='ABUSEIPDB' AND status='FRESH'
                AND data_provenance='REAL' AND observed_at<=? AND expires_at>? AND observed_at>=?
                AND abuse_score>=80 AND total_reports>=3 AND distinct_reporters>=2
                """,Integer.class,ip,at,at,at.minusHours(24))>0;
    }

    private Map<String,Object> providerEvidence(String ip) {
        if (ip==null) return Map.of("status","UNAVAILABLE");
        var rows=jdbc.queryForList("""
                SELECT provider,status,data_provenance,abuse_score,total_reports,distinct_reporters,observed_at,expires_at
                FROM siem_ip_intelligence WHERE ip_address=? AND provider='ABUSEIPDB'
                """,ip);
        if (rows.isEmpty()) return Map.of("status","UNAVAILABLE");
        var row=new LinkedHashMap<>(rows.getFirst());
        row.put("source_ip",ip);
        for(String name:List.of("observed_at","expires_at")) if(row.get(name)!=null) row.put(name,dateTime(row.get(name)).toInstant(ZoneOffset.UTC).toString());
        return row;
    }

    private Hold lockHold(String key,Actor a,String op,Policy p,LocalDateTime at) {
        jdbc.update("""
                INSERT IGNORE INTO siem_postlogin_holds
                (hold_key,user_id,session_pseudonym,operation,policy_id,policy_version,decision_id,starts_at,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,key,a.userId(),a.session().sessionPseudonym(),op,PostloginDecisionPolicy.ID,p.version(),"NONE",at,at);
        return findHold(key,true);
    }
    private Hold startHold(String key,String decision,LocalDateTime at,long policyVersion) {
        jdbc.update("""
                UPDATE siem_postlogin_holds SET decision_id=?,starts_at=?,expires_at=?,released_at=NULL,released_by=NULL,
                release_reason=NULL,policy_version=?,version=version+1 WHERE hold_key=?
                """,decision,at,at.plusSeconds(600),policyVersion,key);
        return new Hold(decision,at.plusSeconds(600),null);
    }
    private Hold findHold(String key,boolean lock) {
        var rows=jdbc.query("SELECT * FROM siem_postlogin_holds WHERE hold_key=?"+(lock?" FOR UPDATE":""),
                (r,n)->new Hold(r.getString("decision_id"),time(r,"expires_at"),time(r,"released_at")),key);
        return rows.isEmpty()?null:rows.getFirst();
    }
    private boolean releasedGrace(Hold h,LocalDateTime at) { return h!=null && h.released()!=null && h.expires().isAfter(at); }
    private Map<String,Object> findRequest(Actor a,String challenge,String request) {
        var rows=jdbc.queryForList("SELECT * FROM siem_postlogin_decisions WHERE user_id=? AND session_pseudonym=? AND challenge_id=? AND request_id=?",
                a.userId(),a.session().sessionPseudonym(),challenge,request);
        return rows.isEmpty()?null:rows.getFirst();
    }
    private Map<String,Object> findDecision(String id) { return jdbc.queryForMap("SELECT * FROM siem_postlogin_decisions WHERE id=?",id); }
    private PostloginActionException prior(Map<String,Object> r) {
        if ("HELD".equals(r.get("outcome"))) {
            var h=findHold((String)r.get("hold_key"),false);
            if (h!=null && h.active(now())) return held(h);
        }
        return new PostloginActionException("PENDING".equals(r.get("outcome"))?PostloginActionException.Kind.REQUEST_IN_PROGRESS:
                PostloginActionException.Kind.REPLAY_REJECTED,"Yeu cau nay da duoc xu ly. Hay thu lai bang mot lan xac nhan moi.",(String)r.get("id"),null);
    }
    private void requireBound(Actor a,User user,SensitiveActionConfirmation action) {
        if (!a.userId().equals(user.getId()) || (user.getAuthVersion()==null?0:user.getAuthVersion())!=a.authVersion()
                || !a.userId().equals(action.getUserId()) || !a.session().sessionPseudonym().equals(action.getSessionPseudonym())
                || a.authVersion()!=action.getAuthVersion()) throw stale(null);
    }
    private PostloginActionException held(Hold h) {
        int seconds=(int)Math.max(1,Duration.between(now(),h.expires()).toSeconds()+1);
        return new PostloginActionException(PostloginActionException.Kind.TEMP_HOLD,
                "Thao tac nay tam dung de bao ve tai khoan. Thu lai sau khi het han hoac lien he SOC.",h.decisionId(),seconds);
    }
    private PostloginActionException stale(String id) { return new PostloginActionException(PostloginActionException.Kind.STALE_DECISION,
            "Yeu cau bao ve da thay doi. Hay thu lai.",id,null); }
    private String key(Actor a,String operation) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                String.join("\u0000",PostloginDecisionPolicy.ID,a.userId(),a.session().sessionPseudonym(),operation).getBytes(StandardCharsets.UTF_8))); }
        catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }
    private String write(Object value) {
        try { return json.writeValueAsString(value); } catch (Exception invalid) { throw new IllegalArgumentException("Invalid decision data",invalid); }
    }
    static LocalDateTime time(ResultSet r,String column) throws SQLException {
        var value=r.getTimestamp(column);return value==null?null:value.toLocalDateTime();
    }
    static LocalDateTime dateTime(Object value) {
        return value instanceof LocalDateTime local ? local : ((java.sql.Timestamp)value).toLocalDateTime();
    }
    private LocalDateTime now() { return LocalDateTime.now(clock).truncatedTo(ChronoUnit.MICROS); }
}
