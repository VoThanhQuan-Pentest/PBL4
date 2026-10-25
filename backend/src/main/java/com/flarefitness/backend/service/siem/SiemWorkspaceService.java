package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.dto.siem.SiemDtos;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SiemWorkspaceService {
    public record Reference(@NotBlank String index,@NotBlank String id) { }
    public record Create(@NotBlank @Size(max=200) String title,@NotEmpty @Size(max=20) List<@Valid Reference> events) { }
    private final SiemEvidenceService evidence;
    private final SiemIncidentRepository incidents;
    private final SiemIncidentService workflow;
    private final JdbcTemplate jdbc;
    private final com.flarefitness.backend.repository.UserRepository users;
    public SiemWorkspaceService(SiemEvidenceService evidence,SiemIncidentRepository incidents,SiemIncidentService workflow,JdbcTemplate jdbc,com.flarefitness.backend.repository.UserRepository users) {
        this.evidence=evidence;this.incidents=incidents;this.workflow=workflow;this.jdbc=jdbc;this.users=users;
    }
    public record EvidenceScope(SiemDtos.Incident incident,SiemEvidenceService.Filter filter,Set<String> references,Set<String> eventIds,boolean fixture) { }
    @Transactional(readOnly=true)
    public EvidenceScope scope(String id,int size) {
        if(size<1 || size>100)throw new BadRequestException("Evidence page size must be 1–100.");
        var incident=workflow.incidentProjection(id);
        Set<String> refs=new HashSet<>(jdbc.query("SELECT elastic_index,elastic_id FROM siem_evidence_refs WHERE incident_id=?",
                (r,n)->r.getString(1)+"\n"+r.getString(2),id));
        Set<String> ids=new HashSet<>(jdbc.query("SELECT a.observed_attempt_id FROM siem_postlogin_decisions d JOIN sensitive_action_confirmations a ON a.id=d.challenge_id WHERE d.incident_id=? AND a.observed_attempt_id IS NOT NULL",(r,n)->r.getString(1),id));
        ids.addAll(jdbc.query("SELECT execution_event_id FROM siem_postlogin_decisions WHERE incident_id=? AND execution_event_id IS NOT NULL",(r,n)->r.getString(1),id));
        ids.addAll(jdbc.query("SELECT r.source_event_id FROM siem_signature_requests r JOIN siem_recurrence_episodes e ON e.id=r.episode_id WHERE e.incident_id=?",(r,n)->r.getString(1),id));
        ids.addAll(jdbc.query("SELECT e.event_id FROM siem_auth_finding_events e JOIN siem_auth_findings f ON f.id=e.finding_id WHERE f.incident_id=?",(r,n)->r.getString(1),id));
        LocalDateTime from=incident.firstSeen().minusMinutes(5),to=incident.lastSeen().plusMinutes(5);
        if(Duration.between(from,to).compareTo(Duration.ofDays(30))>0)from=to.minusDays(30);
        return new EvidenceScope(incident,new SiemEvidenceService.Filter(from,to,null,null,incident.sourceIp(),incident.targetUserId(),size),Set.copyOf(refs),Set.copyOf(ids),
                incident.classificationReason()!=null&&incident.classificationReason().contains("DEMO_ONLY_WORKFLOW_FIXTURE"));
    }
    @Transactional(readOnly=true)
    public SiemEvidenceService.Page incidentEvidence(String id,String cursor,int size) {
        return incidentEvidence(id,cursor,size,true);
    }
    @Transactional(readOnly=true)
    public SiemEvidenceService.Page incidentEvidence(String id,String cursor,int size,boolean includeRelated) {
        var scope=scope(id,size);
        if(scope.fixture() || scope.references().isEmpty()&&scope.eventIds().isEmpty()&&(!includeRelated || scope.incident().sourceIp()==null&&scope.incident().targetUserId()==null))
            return new SiemEvidenceService.Page(List.of(),null,"NO_DETECTION_LOG");
        return evidence.search(scope.filter(),cursor,id,scope.references(),scope.eventIds(),includeRelated&&scope.references().isEmpty());
    }
    @Transactional
    public SiemDtos.Incident create(Create input,Authentication authentication) {
        if (authentication==null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal actor))
            throw new AccessDeniedException("SOC session required.");
        List<JsonNode> hits=input.events.stream().map(ref->evidence.fetch(ref.index,ref.id)).toList();
        List<LocalDateTime> times=hits.stream().map(hit->{
            try { return OffsetDateTime.parse(hit.path("_source").path("@timestamp").asText()).atZoneSameInstant(ZoneOffset.UTC).toLocalDateTime(); }
            catch (RuntimeException e) { throw new BadRequestException("Evidence timestamp missing or invalid."); }
        }).sorted().toList();
        Set<String> ips=new HashSet<>();
        hits.forEach(hit->{String ip=hit.path("_source").path("source").path("ip").asText();if(!ip.isBlank())ips.add(ip);});
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        SiemIncident incident=new SiemIncident();
        incident.setId("siem-incident-"+UUID.randomUUID());incident.setGroupingKey("manual:"+UUID.randomUUID());
        incident.setOrigin(IncidentOrigin.MANUAL);incident.setQueueTier(IncidentQueueTier.L1);
        incident.setNature(IncidentNature.UNKNOWN);incident.setSourceIp(ips.size()==1?ips.iterator().next():null);
        Set<String> targets=new HashSet<>();
        for(JsonNode hit:hits){var source=hit.path("_source");String target=source.path("target").path("user").path("id").asText();
            if(target.isBlank())target=source.path("user").path("id").asText();if(!target.isBlank())targets.add(target);
        }
        if(targets.size()==1)users.findById(targets.iterator().next()).filter(u->!Boolean.TRUE.equals(u.getDeleted()))
            .ifPresent(u->incident.setTargetUserId(u.getId()));
        incident.setTitle(input.title.trim());incident.setRuleId("MANUAL_EVENT_REFERENCE");incident.setSourceSeverity("medium");
        incident.setScore(0);incident.setSeverity(IncidentSeverity.MEDIUM);incident.setClassification(IncidentClassification.INVESTIGATE);
        incident.setClassificationReason("Manual investigation from verified Elasticsearch event references; no automatic detection asserted.");
        incident.setMissingData(false);incident.setStatus(IncidentStatus.NEW);incident.setConclusion(IncidentConclusion.UNREVIEWED);
        incident.setFirstSeen(times.getFirst());incident.setLastSeen(times.getLast());incident.setBucketStart(times.getFirst().truncatedTo(ChronoUnit.HOURS));
        incident.setAlertCount(0);incident.setDistinctRuleCount(0);incident.setCreatedAt(now);incident.setUpdatedAt(now);
        incidents.saveAndFlush(incident);
        for(JsonNode hit:hits) jdbc.update("INSERT IGNORE INTO siem_evidence_refs (incident_id,elastic_index,elastic_id,trace_id,created_at) VALUES (?,?,?,?,?)",
                incident.getId(),hit.path("_index").asText(),hit.path("_id").asText(),hit.path("_source").path("trace").path("id").asText(null),now);
        jdbc.update("INSERT INTO siem_incident_history (id,incident_id,actor_user_id,action,detail,ngay_tao) VALUES (?,?,?,?,?,?)",
                "siem-history-"+UUID.randomUUID(),incident.getId(),actor.getUser().getId(),"MANUAL_CASE_CREATED","Verified ELK references: "+hits.size(),now);
        return workflow.getIncident(incident.getId()).incident();
    }
}
