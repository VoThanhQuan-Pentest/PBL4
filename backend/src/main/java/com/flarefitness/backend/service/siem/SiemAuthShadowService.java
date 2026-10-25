package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.BadRequestException;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Asynchronous candidate observations; never writes holds, incidents, sessions or prevention policies. */
@Service
public class SiemAuthShadowService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final SiemUebaGateway gateway;
    private final boolean enabled;
    private final String manifest;
    private final Set<String> accounts;
    public SiemAuthShadowService(JdbcTemplate jdbc,ObjectMapper json,SiemUebaGateway gateway,
            @Value("${siem.auth.shadow.enabled:false}") boolean enabled,
            @Value("${siem.auth.shadow.manifest-sha256:}") String manifest,
            @Value("${siem.auth.shadow.account-allowlist:}") String accountList){
        this.jdbc=jdbc;this.json=json;this.gateway=gateway;this.enabled=enabled;this.manifest=manifest;
        Set<String> parsed=new HashSet<>();for(String item:accountList.split(","))if(!item.isBlank())parsed.add(item.trim());
        if(parsed.size()>3||parsed.stream().anyMatch(s->!s.matches("[A-Za-z0-9_-]{1,64}")))throw new IllegalArgumentException("At most three explicit shadow practice customers allowed.");
        accounts=Set.copyOf(parsed);
    }
    public Map<String,Object> status(){return Map.of("scope","PILOT_ONLY","mode",enabled?"SHADOW":"OFF","schema",7,"feature_count",81,"automatic_enforcement",false,"configured",manifest.matches("[a-f0-9]{64}"),"allowlisted_accounts",accounts.size(),"source_scope","BASELINE_PROJECT_LIMITED_DECISIONS");}
    @Scheduled(initialDelayString="${siem.auth.shadow.initial-delay-ms:10000}",fixedDelayString="${siem.auth.shadow.interval-ms:5000}")
    @Transactional
    public void process(){
        if(!enabled||accounts.isEmpty()||!manifest.matches("[a-f0-9]{64}"))return;
        // A separate queue: the baseline publisher cannot consume these recommendations as holds.
        Set<String> baselineScope=new HashSet<>();
        try{var raw=jdbc.queryForObject("SELECT account_allowlist_json FROM siem_postlogin_policy WHERE id=?",String.class,PostloginDecisionPolicy.ID);for(var entry:json.readTree(raw))baselineScope.add(entry.asText());}
        catch(Exception unavailable){return;}
        for(String account:accounts){
            if(!baselineScope.contains(account))continue; // Observation scope never silently expands the accepted project population.
            var customer=jdbc.queryForList("SELECT role FROM tbl_nguoi_dung WHERE id=? AND is_deleted=0",account);
            if(customer.isEmpty()||!"CUSTOMER".equals(com.flarefitness.backend.security.CurrentUserPrincipal.toAuthority(customer.getFirst().get("role").toString()).replace("ROLE_","")))continue;
            var decisions=jdbc.queryForList("SELECT d.*,a.observed_attempt_id FROM siem_postlogin_decisions d JOIN sensitive_action_confirmations a ON a.id=d.challenge_id WHERE d.user_id=? AND d.as_of>=? AND d.as_of<=? AND NOT EXISTS(SELECT 1 FROM siem_shadow_assessments s WHERE s.snapshot_id=d.snapshot_id AND s.model_manifest_sha256=?) ORDER BY d.as_of,d.id LIMIT 8",account,LocalDateTime.now(ZoneOffset.UTC).minusMinutes(5),LocalDateTime.now(ZoneOffset.UTC),manifest);
            for(var decision:decisions)observe(decision);
        }
    }
    private void observe(Map<String,Object> decision){
        LocalDateTime at=PostloginDecisionService.dateTime(decision.get("as_of")),now=LocalDateTime.now(ZoneOffset.UTC);
        String id="auth-shadow-"+UUID.randomUUID(),snapshot=decision.get("snapshot_id").toString(),account=decision.get("user_id").toString();
        int inserted=jdbc.update("INSERT IGNORE INTO siem_shadow_assessments(id,snapshot_id,user_id,incident_id,model_manifest_sha256,feature_schema_version,status,features_json,coverage_json,as_of,created_at,updated_at) VALUES (?,?,?,?,?,7,'PENDING','{}','{}',?,?,?)",id,snapshot,account,decision.get("incident_id"),manifest,at,now,now);
        if(inserted==0)return;
        try {
            var source=jdbc.query("SELECT * FROM siem_security_events WHERE id=?",(r,n)->new PostloginShadowFeatures.Observation(SiemAuthCorrelationService.event(r),r.getString("challenge_reference")),decision.get("execution_event_id"));
            if(source.isEmpty()){undetermined(id,"EXECUTION_EVENT_NOT_OBSERVED",now);return;}
            var current=source.getFirst().event();
            // Use the decision's as_of for all extra features; its original event timestamp may be earlier.
            current=new AuthInvestigationRules.Event(current.id(),current.requestId(),at,current.type(),current.action(),current.outcome(),current.actor(),current.target(),current.fingerprint(),current.keyId(),current.source(),current.ua(),current.session(),current.operation(),current.reason());
            var rows=jdbc.query("SELECT * FROM siem_security_events WHERE event_timestamp>=? AND event_timestamp<? AND (source_ip=? OR actor_user_id=? OR target_user_id=?) ORDER BY event_timestamp,id LIMIT 10001",
                    (r,n)->new PostloginShadowFeatures.Observation(SiemAuthCorrelationService.event(r),r.getString("challenge_reference")),at.minusMinutes(30),at,current.source(),account,account);
            String fingerprintVersion=current.keyId();
            boolean covered=rows.size()<=10000&&current.requestId()!=null&&rows.stream().allMatch(o->o.event().requestId()!=null)
                    &&rows.stream().filter(o->"LOGIN".equals(o.event().action())&&"FAILURE".equals(o.event().outcome())).allMatch(o->o.event().targetKey()!=null&&(o.event().target()!=null||Objects.equals(o.event().keyId(),fingerprintVersion)));
            var login=jdbc.query("SELECT * FROM siem_security_events WHERE actor_user_id=? AND session_pseudonym=? AND action='LOGIN' AND outcome='SUCCESS' AND event_timestamp<? AND event_timestamp>=? ORDER BY event_timestamp LIMIT 1",
                    (r,n)->new PostloginShadowFeatures.Observation(SiemAuthCorrelationService.event(r),r.getString("challenge_reference")),account,current.session(),at,at.minusDays(1));
            List<PostloginShadowFeatures.Observation> context=new ArrayList<>(rows);for(var entry:login)if(context.stream().noneMatch(o->o.event().id().equals(entry.event().id())))context.add(entry);
            @SuppressWarnings("unchecked") Map<String,Object> baseline=json.readValue(decision.get("feature_snapshot_json").toString(),Map.class);
            var result=PostloginShadowFeatures.build(baseline,current,context,covered);
            if(!result.covered()||!Boolean.TRUE.equals(baseline.get("baseline_established"))){undetermined(id,result.covered()?"COLD":result.reason(),now);return;}
            var ids=context.stream().map(o->o.event().id()).sorted().toList();
            jdbc.update("UPDATE siem_shadow_assessments SET features_json=?,coverage_json=? WHERE id=?",json.writeValueAsString(result.packet()),json.writeValueAsString(Map.of("source_event_id",current.id(),"context_count",ids.size(),"context_set_sha256",SiemAuthCorrelationService.hash(String.join("\n",ids)),"scope","PILOT_ONLY")),id);
            var assessment=gateway.scoreAuthShadow(result.packet(),manifest);String recommendation=assessment.path("recommendation").asText();
            if(!Set.of("ROUTINE","REVIEW","OPS","UNDETERMINED").contains(recommendation))throw new IllegalArgumentException("Invalid shadow recommendation");
            jdbc.update("UPDATE siem_shadow_assessments SET status='COMPLETED',recommendation=?,context_class=?,raw_score=?,result_json=?,updated_at=? WHERE id=?",recommendation,assessment.path("context").isNull()?null:assessment.path("context").asText(),assessment.path("raw_score").isNumber()?assessment.path("raw_score").doubleValue():null,json.writeValueAsString(assessment),LocalDateTime.now(ZoneOffset.UTC),id);
        }catch(Exception unavailable){jdbc.update("UPDATE siem_shadow_assessments SET status='FAILED',recommendation='UNDETERMINED',result_json=?,updated_at=? WHERE id=?","{\"reason\":\"SHADOW_UNAVAILABLE_BASELINE_UNCHANGED\"}",LocalDateTime.now(ZoneOffset.UTC),id);}
    }
    private void undetermined(String id,String reason,LocalDateTime at)throws com.fasterxml.jackson.core.JsonProcessingException {
        jdbc.update("UPDATE siem_shadow_assessments SET status='UNDETERMINED',recommendation='UNDETERMINED',result_json=?,updated_at=? WHERE id=?",json.writeValueAsString(Map.of("reason",reason,"scope","PILOT_ONLY")),at,id);
    }
    public List<Map<String,Object>> list(String incident,String account,LocalDateTime from,LocalDateTime to,int size){
        if(size<1||size>100||from==null||to==null||!from.isBefore(to)||Duration.between(from,to).compareTo(Duration.ofDays(31))>0)throw new BadRequestException("Invalid shadow query range or page size.");
        for(String value:new String[]{incident,account})if(value!=null&&!value.matches("[A-Za-z0-9_-]{1,128}"))throw new BadRequestException("Invalid shadow query identity.");
        String sql="SELECT id,snapshot_id,user_id,incident_id,model_manifest_sha256,status,recommendation,context_class,raw_score,as_of,created_at FROM siem_shadow_assessments WHERE as_of>=? AND as_of<=?";
        List<Object> args=new ArrayList<>(List.of(from,to));if(incident!=null){sql+=" AND incident_id=?";args.add(incident);}if(account!=null){sql+=" AND user_id=?";args.add(account);}sql+=" ORDER BY as_of DESC,id LIMIT ?";args.add(size);
        return jdbc.queryForList(sql,args.toArray());
    }
}
