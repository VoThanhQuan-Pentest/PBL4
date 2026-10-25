package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.exception.*;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import jakarta.validation.constraints.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Durable server-event correlation. Its only optional side effect is an investigation incident. */
@Service
public class SiemAuthCorrelationService {
    private final JdbcTemplate jdbc;
    private final SiemIncidentRepository incidents;
    public SiemAuthCorrelationService(JdbcTemplate jdbc,SiemIncidentRepository incidents){this.jdbc=jdbc;this.incidents=incidents;}
    public record Policy(String mode,String definitionVersion,long version) { }
    public record Change(@NotBlank String mode,@NotNull Long expectedVersion,@NotBlank @Pattern(regexp="[A-Za-z0-9_-]{8,64}") String requestId,@NotBlank @Size(min=10,max=1000) String reason) { }
    public Policy policy(){return jdbc.queryForObject("SELECT * FROM siem_auth_correlation_policy WHERE id=1",(r,n)->new Policy(r.getString("mode"),r.getString("definition_version"),r.getLong("version")));}
    public List<Map<String,Object>> policyHistory(){return jdbc.queryForList("SELECT request_id,actor_user_id,mode,reason,resulting_version,created_at FROM siem_auth_policy_requests ORDER BY created_at DESC,request_id LIMIT 50");}
    @Transactional
    public Policy change(Change request,Authentication authentication){
        if(authentication==null||!(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)||authentication.getAuthorities().stream().noneMatch(a->"ROLE_ADMIN".equals(a.getAuthority())))throw new AccessDeniedException("Admin required.");
        if(request.reason()==null||request.reason().trim().length()<10||request.reason().trim().length()>1000)throw new BadRequestException("Reason must contain 10–1000 characters.");
        if(!Set.of("OFF","OBSERVE","ALERT").contains(request.mode()))throw new BadRequestException("Invalid correlation mode.");
        jdbc.queryForList("SELECT id FROM siem_auth_correlation_policy WHERE id=1 FOR UPDATE");
        String hash=hash(request.mode()+"|"+request.expectedVersion()+"|"+request.reason().trim());
        var prior=jdbc.queryForList("SELECT actor_user_id,request_hash,resulting_version FROM siem_auth_policy_requests WHERE request_id=?",request.requestId());
        if(!prior.isEmpty()){
            if(!prior.getFirst().get("actor_user_id").equals(principal.getUser().getId())||!prior.getFirst().get("request_hash").equals(hash))throw new ConflictException("Request ID already used for a different policy change.");
            return new Policy(request.mode(),AuthInvestigationRules.VERSION,((Number)prior.getFirst().get("resulting_version")).longValue());
        }
        if(jdbc.update("UPDATE siem_auth_correlation_policy SET mode=?,version=version+1,updated_at=? WHERE id=1 AND version=?",request.mode(),LocalDateTime.now(ZoneOffset.UTC),request.expectedVersion())!=1)throw new ConflictException("Policy version changed.");
        jdbc.update("INSERT INTO siem_auth_policy_requests(request_id,actor_user_id,request_hash,reason,mode,resulting_version,created_at) VALUES (?,?,?,?,?,?,?)",request.requestId(),principal.getUser().getId(),hash,request.reason().trim(),request.mode(),request.expectedVersion()+1,LocalDateTime.now(ZoneOffset.UTC));
        return policy();
    }
    @Scheduled(initialDelayString="${siem.auth.correlation.initial-delay-ms:10000}",fixedDelayString="${siem.auth.correlation.interval-ms:5000}")
    @Transactional
    public void process(){
        jdbc.queryForList("SELECT id FROM siem_auth_correlation_policy WHERE id=1 FOR UPDATE");
        Policy policy=policy();if("OFF".equals(policy.mode()))return;
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        var pending=jdbc.query("SELECT e.* FROM siem_security_events e WHERE auth_request_id IS NOT NULL AND event_timestamp>=? AND NOT EXISTS(SELECT 1 FROM siem_auth_processed_events p WHERE p.event_id=e.id) ORDER BY e.ngay_tao,e.id LIMIT 50",(r,n)->event(r),now.minusDays(1));
        for(var current:pending){
            if(jdbc.update("INSERT IGNORE INTO siem_auth_processed_events(event_id,processed_at) VALUES (?,?)",current.id(),now)==0)continue;
            if(current.at().isBefore(now.minusMinutes(5))||current.at().isAfter(now.plusMinutes(2)))continue;
            var rows=jdbc.query("SELECT * FROM siem_security_events WHERE event_timestamp>=? AND event_timestamp<=? AND demo_label IS NULL AND (source_ip=? OR target_user_id=? OR actor_user_id=?) ORDER BY event_timestamp,id LIMIT 10001",
                    (r,n)->event(r),current.at().minusMinutes(30),current.at(),current.source(),current.target(),current.actor());
            boolean fixture=Boolean.TRUE.equals(jdbc.queryForObject("SELECT demo_label IS NOT NULL FROM siem_security_events WHERE id=?",Boolean.class,current.id()));
            if(fixture)continue;
            var signals=AuthInvestigationRules.assess(current,rows,rows.size()<=10000,novelty(current));
            for(var signal:signals)record(signal,current,policy,now);
        }
    }
    private AuthInvestigationRules.Novelty novelty(AuthInvestigationRules.Event current){
        if(current.actor()==null)return new AuthInvestigationRules.Novelty(false,false,false);
        Long windows=jdbc.queryForObject("SELECT COUNT(DISTINCT window_start) FROM siem_account_behavior_windows WHERE account_id=? AND window_end<? AND window_start>=? AND event_count>0 AND demo_label='REAL' AND http_4xx_count=0 AND http_5xx_count=0 AND failed_login_count=0 AND sensitive_action_count=0 AND new_ip_flag=0 AND new_user_agent_flag=0 AND (risk_score IS NULL OR risk_score<30)",Long.class,current.actor(),current.at(),current.at().minusDays(14));
        if(windows==null||windows<30)return new AuthInvestigationRules.Novelty(false,false,false);
        // Novelty is relative to retained pre-session history, never to future/current-session events.
        var login=jdbc.queryForList("SELECT event_timestamp,source_ip,user_agent_family FROM siem_security_events WHERE actor_user_id=? AND session_pseudonym=? AND action='LOGIN' AND outcome='SUCCESS' AND event_timestamp<=? ORDER BY event_timestamp LIMIT 1",current.actor(),current.session(),current.at());
        if(login.isEmpty())return new AuthInvestigationRules.Novelty(false,false,false);
        var row=login.getFirst();LocalDateTime before=PostloginDecisionService.dateTime(row.get("event_timestamp"));
        Long ips=jdbc.queryForObject("SELECT COUNT(*) FROM siem_security_events WHERE actor_user_id=? AND event_timestamp>=? AND event_timestamp<? AND source_ip=?",Long.class,current.actor(),before.minusDays(14),before,row.get("source_ip"));
        Long agents=jdbc.queryForObject("SELECT COUNT(*) FROM siem_security_events WHERE actor_user_id=? AND event_timestamp>=? AND event_timestamp<? AND user_agent_family=?",Long.class,current.actor(),before.minusDays(14),before,row.get("user_agent_family"));
        return new AuthInvestigationRules.Novelty(true,row.get("source_ip")!=null&&ips!=null&&ips==0,row.get("user_agent_family")!=null&&agents!=null&&agents==0);
    }
    private void record(AuthInvestigationRules.Signal signal,AuthInvestigationRules.Event current,Policy policy,LocalDateTime now){
        String grouping=hash(signal.rule()+"|"+signal.group()+"|"+policy.version());
        LocalDateTime first=signal.evidence().stream().map(AuthInvestigationRules.Event::at).min(LocalDateTime::compareTo).orElse(current.at());
        var existing=jdbc.queryForList("SELECT id,incident_id FROM siem_auth_findings WHERE grouping_hash=? AND last_seen>=? ORDER BY last_seen DESC LIMIT 1 FOR UPDATE",grouping,current.at().minusMinutes(30));
        String id=existing.isEmpty()?"auth-finding-"+UUID.randomUUID():existing.getFirst().get("id").toString();
        String incident=existing.isEmpty()?null:(String)existing.getFirst().get("incident_id");
        if(existing.isEmpty())jdbc.update("INSERT INTO siem_auth_findings(id,grouping_hash,rule_id,policy_version,first_seen,last_seen,severity,evidence_count) VALUES (?,?,?,?,?,?,?,0)",id,grouping,signal.rule(),policy.version(),first,current.at(),signal.severity());
        if(incident==null&&"ALERT".equals(policy.mode())){
            var item=new SiemIncident();item.setId("auth-incident-"+UUID.randomUUID());item.setGroupingKey("auth:"+id);item.setServiceId("flare-web");item.setRuleId(signal.rule());
            item.setSourceIp(current.source());item.setTargetUserId(current.target()!=null?current.target():current.actor());item.setOrigin(IncidentOrigin.CORRELATION);item.setQueueTier(IncidentQueueTier.L1);item.setNature(IncidentNature.SECURITY_DETECTION);
            item.setBucketStart(current.at().withSecond(0).withNano(0));item.setTitle("Điều tra tài khoản · "+signal.rule());item.setSourceSeverity(signal.severity());item.setScore(0);item.setSeverity(IncidentSeverity.valueOf(signal.severity()));item.setClassification(IncidentClassification.INVESTIGATE);
            item.setClassificationReason("Server-observed correlation "+AuthInvestigationRules.VERSION+"; requires investigation, does not assert account compromise or model confidence.");item.setStatus(IncidentStatus.NEW);item.setConclusion(IncidentConclusion.UNREVIEWED);item.setFirstSeen(first);item.setLastSeen(current.at());item.setCreatedAt(now);item.setUpdatedAt(now);item.setDistinctRuleCount(1);item.setAlertCount(1);
            incident=incidents.saveAndFlush(item).getId();
            jdbc.update("INSERT INTO siem_incident_history(id,incident_id,actor_user_id,action,detail,ngay_tao) VALUES (?,?,NULL,'AUTH_CORRELATION_CREATED',?,?)","auth-history-"+UUID.randomUUID(),incident,signal.rule()+" / "+AuthInvestigationRules.VERSION,now);
        }
        for(var event:signal.evidence())jdbc.update("INSERT IGNORE INTO siem_auth_finding_events(finding_id,event_id,request_id) VALUES (?,?,?)",id,event.id(),event.requestId());
        jdbc.update("UPDATE siem_auth_findings SET first_seen=LEAST(first_seen,?),last_seen=?,incident_id=?,severity=CASE WHEN severity='HIGH' OR ?='HIGH' THEN 'HIGH' ELSE severity END,evidence_count=(SELECT COUNT(*) FROM siem_auth_finding_events e WHERE e.finding_id=?) WHERE id=?",first,current.at(),incident,signal.severity(),id,id);
        if(incident!=null)jdbc.update("UPDATE siem_incidents SET first_seen=LEAST(first_seen,?),last_seen=?,updated_at=?,severity=CASE WHEN severity='HIGH' OR ?='HIGH' THEN 'HIGH' ELSE severity END,alert_count=(SELECT evidence_count FROM siem_auth_findings WHERE id=?),version=version+1 WHERE id=?",first,current.at(),now,signal.severity(),id,incident);
    }
    static AuthInvestigationRules.Event event(ResultSet r)throws SQLException {
        String type=r.getString("event_type"),action=r.getString("action");
        String requestId=r.getString("auth_request_id");
        if("SENSITIVE_EXECUTE".equals(action)&&r.getString("execution_request_id")!=null){
            String key=hash(r.getString("actor_user_id")+"|"+r.getString("session_pseudonym")+"|"+r.getString("challenge_reference")+"|"+r.getString("execution_request_id"));
            requestId=key.substring(0,8)+"-"+key.substring(8,12)+"-"+key.substring(12,16)+"-"+key.substring(16,20)+"-"+key.substring(20,32);
        }
        return new AuthInvestigationRules.Event(r.getString("id"),requestId,r.getTimestamp("event_timestamp").toLocalDateTime(),type,action,r.getString("outcome"),r.getString("actor_user_id"),r.getString("target_user_id"),r.getString("auth_target_fingerprint"),r.getString("fingerprint_key_id"),r.getString("source_ip"),r.getString("user_agent_family"),r.getString("session_pseudonym"),"SENSITIVE_ACTION_ATTEMPT".equals(type)?action:r.getString("route_group"),r.getString("denial_reason"));
    }
    static String hash(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception impossible){throw new IllegalStateException(impossible);}}
}
