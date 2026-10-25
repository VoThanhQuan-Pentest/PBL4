package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.PostloginDtos;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.exception.*;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PostloginSocService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final PostloginDecisionService guard;
    private final AuditLogService audit;
    public PostloginSocService(JdbcTemplate jdbc,ObjectMapper json,PostloginDecisionService guard,AuditLogService audit) {
        this.jdbc=jdbc;this.json=json;this.guard=guard;this.audit=audit;
    }
    public PostloginDtos.PolicyStatus status() {
        var p=guard.policy();
        return new PostloginDtos.PolicyStatus(p.mode(),"PROJECT_LIMITED","DEMO_ONLY_RULE_DISTILLATION",
                PostloginDecisionPolicy.MODEL,p.version(),guard.operatorHeld(),600,true);
    }
    @Transactional(readOnly=true)
    public PageResponse<PostloginDtos.Summary> list(String incidentId,int page,int size) {
        if (page<0 || page>100000 || size<1 || size>100) throw new BadRequestException("Phan trang khong hop le.");
        if (incidentId!=null && !incidentId.matches("[A-Za-z0-9_-]{1,64}")) throw new BadRequestException("Incident ID khong hop le.");
        String where=incidentId==null?"":" WHERE incident_id=?";
        Object[] countArgs=incidentId==null?new Object[]{}:new Object[]{incidentId};
        long total=jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_decisions"+where,Long.class,countArgs);
        Object[] args=incidentId==null?new Object[]{size,(long)page*size}:new Object[]{incidentId,size,(long)page*size};
        var items=jdbc.query("SELECT * FROM siem_postlogin_decisions"+where+" ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
                (r,n)->summary(r),args);
        return new PageResponse<>(items,page,size,total,(int)Math.ceil((double)total/size),(long)(page+1)*size<total);
    }
    @Transactional(readOnly=true)
    public PostloginDtos.Detail detail(String id) {
        checkId(id);
        var rows=jdbc.query("""
                SELECT d.*,h.released_at,h.released_by,h.release_reason,h.decision_id AS active_hold_decision,
                h.expires_at AS current_hold_expires FROM siem_postlogin_decisions d LEFT JOIN siem_postlogin_holds h
                ON d.hold_key=h.hold_key WHERE d.id=?
                """,(r,n)-> {
                    Instant expires=instant(r,"current_hold_expires"),released=instant(r,"released_at");
                    boolean active=id.equals(r.getString("active_hold_decision")) && expires!=null
                            && expires.isAfter(Instant.now()) && released==null;
                    return new PostloginDtos.Detail(summary(r),r.getString("policy_id"),r.getLong("policy_version"),
                            r.getString("model_version"),r.getString("model_sha256"),r.getString("model_manifest_sha256"),
                            r.getBoolean("baseline_established"),r.getInt("trusted_window_count"),
                            parse(r.getString("reasons_json"),new TypeReference<List<String>>(){}),
                            parse(r.getString("ip_evidence_json"),new TypeReference<Map<String,Object>>(){}),
                            parse(r.getString("feature_snapshot_json"),new TypeReference<Map<String,Object>>(){}),
                            active,released,r.getString("released_by"),r.getString("release_reason"),reviews(id));
                },id);
        if (rows.isEmpty()) throw new ResourceNotFoundException("Khong tim thay quyet dinh.");
        return rows.getFirst();
    }
    @Transactional
    public PostloginDtos.Detail release(String id,PostloginDtos.Release request,Authentication authentication) {
        var actor=actor(authentication);
        var row=lockAndAuthorize(id,request.expectedVersion(),actor);
        String reason=reason(request.reason());
        if (!id.equals(row.get("hold_decision")) || row.get("released_at")!=null
                || !PostloginDecisionService.dateTime(row.get("hold_expires")).toInstant(ZoneOffset.UTC).isAfter(Instant.now())) {
            throw new ConflictException("Lenh tam dung da het han, da mo hoac da duoc thay the. Hay tai lai.");
        }
        jdbc.update("UPDATE siem_postlogin_holds SET released_at=?,released_by=?,release_reason=?,version=version+1 WHERE hold_key=?",
                LocalDateTime.now(ZoneOffset.UTC),actor.getUser().getId(),reason,row.get("hold_key"));
        jdbc.update("UPDATE siem_postlogin_decisions SET updated_at=?,version=version+1 WHERE id=?",
                LocalDateTime.now(ZoneOffset.UTC),id);
        appendReview(id,actor,"UNDETERMINED",reason);
        audit.success("POSTLOGIN_HOLD_RELEASED",actor.getUser().getId(),(String)row.get("user_id"),"DECISION",id);
        return detail(id);
    }
    @Transactional
    public PostloginDtos.Detail review(String id,PostloginDtos.ReviewRequest request,Authentication authentication) {
        var actor=actor(authentication);
        var row=lockAndAuthorize(id,request.expectedVersion(),actor);
        appendReview(id,actor,request.verdict().name(),reason(request.reason()));
        jdbc.update("UPDATE siem_postlogin_decisions SET updated_at=?,version=version+1 WHERE id=?",LocalDateTime.now(ZoneOffset.UTC),id);
        audit.success("POSTLOGIN_ANALYST_REVIEW",actor.getUser().getId(),(String)row.get("user_id"),"DECISION",id);
        return detail(id);
    }
    private Map<String,Object> lockAndAuthorize(String id,long expected,CurrentUserPrincipal actor) {
        checkId(id);
        jdbc.queryForList("SELECT id FROM siem_postlogin_policy WHERE id=? FOR UPDATE",PostloginDecisionPolicy.ID);
        var keys=jdbc.queryForList("SELECT hold_key FROM siem_postlogin_decisions WHERE id=?",id);
        if (keys.isEmpty()) throw new ResourceNotFoundException("Khong tim thay quyet dinh.");
        jdbc.queryForList("SELECT hold_key FROM siem_postlogin_holds WHERE hold_key=? FOR UPDATE",keys.getFirst().get("hold_key"));
        var row=jdbc.queryForMap("""
                SELECT d.*,h.decision_id AS hold_decision,h.expires_at AS hold_expires,h.released_at
                FROM siem_postlogin_decisions d JOIN siem_postlogin_holds h ON d.hold_key=h.hold_key
                WHERE d.id=? FOR UPDATE
                """,id);
        if (((Number)row.get("version")).longValue()!=expected) throw new ConflictException("Quyet dinh da thay doi. Hay tai lai.");
        if (!"ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(actor.getUser().getRole()))) {
            var incident=jdbc.queryForList("SELECT * FROM siem_incidents WHERE id=? FOR UPDATE",row.get("incident_id"));
            if (incident.isEmpty() || !"L2".equals(incident.getFirst().get("queue_tier"))
                    || !"IN_PROGRESS".equals(incident.getFirst().get("status"))
                    || !actor.getUser().getId().equals(incident.getFirst().get("assignee_user_id"))) {
                throw new AccessDeniedException("Can nhan xu ly incident lien ket o L2 truoc khi thay doi quyet dinh.");
            }
        }
        return row;
    }
    private CurrentUserPrincipal actor(Authentication authentication) {
        if (authentication==null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal p)
                || !Set.of("ROLE_SOC_L2","ROLE_ADMIN").contains(CurrentUserPrincipal.toAuthority(p.getUser().getRole()))) {
            throw new AccessDeniedException("Chi SOC L2 hoac Admin duoc mo tam dung va danh gia.");
        }
        return p;
    }
    private void appendReview(String id,CurrentUserPrincipal actor,String verdict,String reason) {
        jdbc.update("INSERT INTO siem_postlogin_reviews (id,decision_id,actor_user_id,verdict,reason,created_at) VALUES (?,?,?,?,?,?)",
                "plr-"+UUID.randomUUID(),id,actor.getUser().getId(),verdict,reason,LocalDateTime.now(ZoneOffset.UTC));
    }
    private List<PostloginDtos.Review> reviews(String id) {
        return jdbc.query("SELECT * FROM siem_postlogin_reviews WHERE decision_id=? ORDER BY created_at,id",
                (r,n)->new PostloginDtos.Review(r.getString("id"),r.getString("actor_user_id"),r.getString("verdict"),r.getString("reason"),instant(r,"created_at")),id);
    }
    private PostloginDtos.Summary summary(ResultSet r) throws SQLException {
        double percentile=r.getDouble("normal_percentile"); Double value=r.wasNull()?null:percentile;
        return new PostloginDtos.Summary(r.getString("id"),r.getString("user_id"),r.getString("operation"),r.getString("mode"),
                r.getString("decision"),r.getString("outcome"),r.getString("context_class"),value,r.getString("incident_id"),
                instant(r,"created_at"),instant(r,"hold_expires_at"),r.getLong("version"));
    }
    private Instant instant(ResultSet r,String column) throws SQLException {
        var at=r.getTimestamp(column);return at==null?null:at.toLocalDateTime().toInstant(ZoneOffset.UTC);
    }
    private <T>T parse(String value,TypeReference<T> type) {
        try { return json.readValue(value,type); } catch (Exception invalid) { throw new ServiceUnavailableException("Du lieu quyet dinh khong hop le."); }
    }
    private void checkId(String id) { if (id==null || !id.matches("pld-[0-9a-f-]{36}")) throw new BadRequestException("Decision ID khong hop le."); }
    private String reason(String text) {
        if (text==null || text.trim().length()<10 || text.length()>1000 || text.chars().anyMatch(c->Character.isISOControl(c)&&c!='\n'&&c!='\t')) {
            throw new BadRequestException("Can ly do 10-1000 ky tu.");
        }
        return text.trim();
    }
}
