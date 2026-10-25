package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.service.AuditLogService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Durable decision outbox -> existing SOC workflow. No remote provider call or enforcement here. */
@Component
public class PostloginIncidentPublisher {
    private final JdbcTemplate jdbc;
    private final SiemIncidentRepository incidents;
    private final AuditLogService audit;
    private final boolean enabled;
    public PostloginIncidentPublisher(JdbcTemplate jdbc,SiemIncidentRepository incidents,AuditLogService audit,
            @Value("${siem.postlogin.enabled:false}") boolean enabled) {
        this.jdbc=jdbc;this.incidents=incidents;this.audit=audit;this.enabled=enabled;
    }
    @Scheduled(fixedDelayString="${siem.postlogin.publish-interval-ms:5000}")
    @Transactional
    public void publishPending() {
        if (!enabled) return;
        var rows=jdbc.queryForList("""
                SELECT * FROM siem_postlogin_decisions WHERE incident_id IS NULL AND outcome<>'PENDING'
                AND decision IN ('TEMP_HOLD','STEP_UP','OPS_ALERT') ORDER BY created_at,id LIMIT 50 FOR UPDATE SKIP LOCKED
                """);
        for (var row:rows) {
            String decision=(String)row.get("decision");
            LocalDateTime at=PostloginDecisionService.dateTime(row.get("created_at"));
            LocalDateTime bucket=at.withMinute(at.getMinute()/15*15).withSecond(0).withNano(0);
            String group="postlogin:"+row.get("hold_key")+":"+bucket+":"+decision+":"+row.get("policy_version");
            if ("TEMP_HOLD".equals(decision)) group += ":"+row.get("id");
            String grouping=group;
            var incident=incidents.findByGroupingKey(grouping).orElseGet(() -> {
                var i=new SiemIncident();
                i.setId("postlogin-"+UUID.randomUUID());i.setGroupingKey(grouping);i.setServiceId("flare-web");
                i.setRuleId(PostloginDecisionPolicy.ID);i.setTargetUserId((String)row.get("user_id"));
                i.setOrigin(IncidentOrigin.UEBA);i.setQueueTier(IncidentQueueTier.L1);
                i.setDetectorModelVersion(PostloginDecisionPolicy.MODEL);i.setBucketStart(bucket);
                boolean ops="OPS_ALERT".equals(decision),hold="TEMP_HOLD".equals(decision);
                i.setNature(ops?IncidentNature.OPERATIONAL_ANOMALY:IncidentNature.ACCOUNT_BEHAVIOR_ANOMALY);
                i.setTitle("[PROJECT_LIMITED] "+decision+" / "+row.get("operation"));
                i.setScore(hold?80:ops?25:50);i.setSourceSeverity(hold?"HIGH":ops?"LOW":"MEDIUM");
                i.setSeverity(hold?IncidentSeverity.HIGH:ops?IncidentSeverity.LOW:IncidentSeverity.MEDIUM);
                i.setClassification(ops?IncidentClassification.POTENTIAL_NOISE:IncidentClassification.INVESTIGATE);
                i.setClassificationReason("Lab decision policy priority; not attack probability. OTP remains required. "+row.get("mode"));
                i.setStatus(IncidentStatus.NEW);i.setConclusion(IncidentConclusion.UNREVIEWED);
                i.setAlertCount(1);i.setDistinctRuleCount(1);i.setFirstSeen(at);i.setLastSeen(at);
                i.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));i.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
                return incidents.saveAndFlush(i);
            });
            jdbc.update("UPDATE siem_postlogin_decisions SET incident_id=?,updated_at=?,version=version+1 WHERE id=? AND incident_id IS NULL",
                    incident.getId(),LocalDateTime.now(ZoneOffset.UTC),row.get("id"));
            audit.success("POSTLOGIN_INCIDENT_LINKED","SYSTEM",(String)row.get("user_id"),"DECISION",(String)row.get("id"));
        }
    }
}
