package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Read projections only. Elasticsearch documents and workflow payloads keep separate provenance. */
@Service
public class SiemInvestigationService {
    private static final Set<String> TYPES=Set.of("ELK","MODEL","NOTE","WORKFLOW");
    private static final Comparator<Ref> ORDER=Comparator.comparing(Ref::at).reversed().thenComparing(Ref::kind).thenComparing(Ref::id);
    private final SiemWorkspaceService workspace;
    private final SiemEvidenceService evidence;
    private final SiemContainmentService containment;
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    private final Map<String,State> cursors=new ConcurrentHashMap<>();

    public SiemInvestigationService(SiemWorkspaceService workspace,SiemEvidenceService evidence,
            SiemContainmentService containment,JdbcTemplate jdbc,ObjectMapper json) {
        this.workspace=workspace;this.evidence=evidence;this.containment=containment;this.jdbc=jdbc;this.json=json;
    }
    public record Summary(SiemDtos.Incident incident,Map<String,SiemEvidenceService.ValueGroup> observed,
            Map<String,String> workflowContext,String sourceStatus,LocalDateTime from,LocalDateTime to,
            List<SiemContainmentService.Action> containment,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) LocalDateTime firstObservedAt) { }
    public record Entry(String id,String kind,LocalDateTime occurredAt,JsonNode elkHit,
            SiemEvidenceService.Association association,JsonNode details) { }
    public record Timeline(List<Entry> content,String nextCursor,String sourceStatus,LocalDateTime asOf) { }
    private record Ref(String id,String kind,LocalDateTime at) { }
    private static final class State {
        String incident,owner,types,elkCursor,sourceStatus;
        boolean related,elkFinished;
        int size,position,elkPosition;
        long expires;
        LocalDateTime asOf,from,to;
        SiemWorkspaceService.EvidenceScope scope;
        List<Ref> refs;
        List<SiemEvidenceService.Item> elk=List.of();
        long cacheBytes;
    }
    public record TrendPoint(String hour,long count) { }
    public record Metrics(long open,long highOpen,long l2Open,long responsePendingFailed,List<TrendPoint> trend) { }
    public Metrics metrics(LocalDateTime from,LocalDateTime to) {
        if(from==null||to==null||!from.isBefore(to)||Duration.between(from,to).compareTo(Duration.ofDays(31))>0)
            throw new BadRequestException("Invalid dashboard range.");
        var counts=jdbc.queryForMap("SELECT COALESCE(SUM(status<>'CLOSED'),0) AS open_count,COALESCE(SUM(status<>'CLOSED' AND severity IN ('HIGH','URGENT')),0) AS high_count,COALESCE(SUM(status<>'CLOSED' AND queue_tier='L2'),0) AS l2_count FROM siem_incidents WHERE last_seen>=? AND last_seen<=?",from,to);
        Long pending=jdbc.queryForObject("SELECT COUNT(*) FROM siem_containment_actions WHERE status IN ('PENDING','FAILED') AND created_at>=? AND created_at<=?",Long.class,from,to);
        Long policies=jdbc.queryForObject("SELECT COUNT(*) FROM siem_prevention_policies WHERE acknowledged_at IS NULL AND published_at>=? AND published_at<=?",Long.class,from,to);
        var trend=jdbc.query("SELECT DATE_FORMAT(last_seen,'%Y-%m-%dT%H:00:00') AS hour,COUNT(*) AS count FROM siem_incidents WHERE last_seen>=? AND last_seen<=? GROUP BY hour ORDER BY hour",(r,n)->new TrendPoint(r.getString(1),r.getLong(2)),from,to);
        return new Metrics(((Number)counts.get("open_count")).longValue(),((Number)counts.get("high_count")).longValue(),((Number)counts.get("l2_count")).longValue(),(pending==null?0:pending)+(policies==null?0:policies),trend);
    }
    public record QueueEntry(SiemDtos.Incident incident,Map<String,SiemEvidenceService.ValueGroup> observed,String sourceStatus,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) LocalDateTime firstObservedAt) { }
    public List<QueueEntry> queue(List<SiemDtos.Incident> incidents){
        return queue(incidents,false);
    }
    public List<QueueEntry> queue(List<SiemDtos.Incident> incidents,boolean includeEventTime){
        if(incidents.size()>100)throw new BadRequestException("At most100 incidents per queue page.");
        Map<String,SiemWorkspaceService.EvidenceScope> scopes=new LinkedHashMap<>();
        for(var incident:incidents)scopes.put(incident.id(),workspace.scope(incident.id(),50));
        var summaries=evidence.aggregateBatch(scopes);
        return incidents.stream().map(incident->{var group=summaries.get(incident.id());return new QueueEntry(incident,group.groups(),group.sourceStatus(),includeEventTime?group.firstObservedAt():null);}).toList();
    }
    public Summary summary(String incident) {
        return summary(incident,false);
    }
    public Summary summary(String incident,boolean includeEventTime) {
        var scope=workspace.scope(incident,50);
        var context=new LinkedHashMap<String,String>();
        if(scope.incident().sourceIp()!=null)context.put("source_ip",scope.incident().sourceIp());
        if(scope.incident().targetUserId()!=null)context.put("target_user_id",scope.incident().targetUserId());
        boolean noDirect=scope.references().isEmpty()&&scope.eventIds().isEmpty();
        var aggregate=scope.fixture()||noDirect?new SiemEvidenceService.Aggregate(Map.of(),"NO_DETECTION_LOG")
                :evidence.aggregate(scope.filter(),scope.references(),scope.eventIds());
        return new Summary(scope.incident(),aggregate.groups(),Map.copyOf(context),aggregate.sourceStatus(),
                scope.filter().from(),scope.filter().to(),containment.list(incident),includeEventTime?aggregate.firstObservedAt():null);
    }
    /** Snapshot workflow references only (bounded), never all native log documents. */
    public Timeline timeline(String incident,String token,String requestedTypes,boolean related,int size) {
        return timeline(incident,token,requestedTypes,related,size,null,null);
    }
    public Timeline timeline(String incident,String token,String requestedTypes,boolean related,int size,LocalDateTime from,LocalDateTime to) {
        if((from==null)!=(to==null)||from!=null&&(!from.isBefore(to)||Duration.between(from,to).compareTo(Duration.ofDays(30))>0))throw new BadRequestException("Timeline requires a valid range up to 30 days.");
        if(size<1||size>100)throw new BadRequestException("Timeline page size must be 1–100.");
        var types=parseTypes(requestedTypes);String key=String.join(",",new TreeSet<>(types));
        State state;
        if(token==null||token.isBlank()) {
            cursors.entrySet().removeIf(e->e.getValue().expires<System.currentTimeMillis());
            if(cursors.size()>=32)throw new ServiceUnavailableException("Too many investigation snapshots.");
            var scope=workspace.scope(incident,100); // frozen direct references and filter for the entire PIT
            if(from!=null)scope=new SiemWorkspaceService.EvidenceScope(scope.incident(),new SiemEvidenceService.Filter(from,to,null,null,scope.filter().ip(),scope.filter().accountId(),100),scope.references(),scope.eventIds(),scope.fixture());
            state=new State();state.scope=scope;state.from=from;state.to=to;state.incident=incident;state.owner=SiemEvidenceService.cursorOwner();state.types=key;
            state.related=related;state.size=size;state.expires=System.currentTimeMillis()+120_000;
            state.asOf=LocalDateTime.now(ZoneOffset.UTC);state.refs=references(incident,state.asOf,types,from,to);
            state.elkFinished=!types.contains("ELK");state.sourceStatus=state.elkFinished?"NOT_REQUESTED":"AVAILABLE";
            if(!state.elkFinished&&(scope.fixture()||!related&&scope.references().isEmpty()&&scope.eventIds().isEmpty())){state.elkFinished=true;state.sourceStatus="NO_DETECTION_LOG";}
        }else {
            state=cursors.get(token);
            if(state==null||state.expires<System.currentTimeMillis()||!state.incident.equals(incident)
                    ||!state.owner.equals(SiemEvidenceService.cursorOwner())||!state.types.equals(key)
                    ||state.related!=related||state.size!=size||!Objects.equals(from,state.from)||!Objects.equals(to,state.to))
                throw new BadRequestException("Timeline cursor expired or does not match this session/filter.");
            if(!cursors.remove(token,state))throw new BadRequestException("Timeline cursor was already consumed.");
        }
        List<Entry> content=new ArrayList<>();
        while(content.size()<size) {
            refill(state);
            Ref workflow=state.position<state.refs.size()?state.refs.get(state.position):null;
            SiemEvidenceService.Item log=state.elkPosition<state.elk.size()?state.elk.get(state.elkPosition):null;
            if(workflow==null&&log==null)break;
            if(log!=null&&(workflow==null||!logTime(log).isBefore(workflow.at()))) {
                content.add(new Entry(log.elkHit().path("_index").asText()+"/"+log.elkHit().path("_id").asText(),"ELK",logTime(log),log.elkHit(),log.association(),null));
                state.elkPosition++;
            }else {content.add(workflowEntry(workflow));state.position++;}
        }
        if(state.elkPosition>0){state.elk=List.copyOf(state.elk.subList(state.elkPosition,state.elk.size()));state.elkPosition=0;}
        boolean more=state.position<state.refs.size()||!state.elk.isEmpty()||!state.elkFinished;
        String next=null;
        if(more){
            state.cacheBytes=state.refs.size()*160L+state.elk.stream().mapToLong(item->item.elkHit().toString().length()*4L).sum();
            synchronized(cursors){
                long bytes=cursors.values().stream().mapToLong(value->value.cacheBytes).sum();
                if(cursors.size()>=32||bytes+state.cacheBytes>64L*1024*1024)throw new ServiceUnavailableException("Investigation cursor memory budget exhausted; narrow the range or retry.");
                next=UUID.randomUUID().toString();cursors.put(next,state);
            }
        }
        String status=Set.of("UNAVAILABLE","DISABLED","RAW_REFUSED","BUSY").contains(state.sourceStatus)&&!state.refs.isEmpty()?"PARTIAL_"+state.sourceStatus:state.sourceStatus;
        return new Timeline(List.copyOf(content),next,status,state.asOf);
    }
    private void refill(State state) {
        if(state.elkPosition<state.elk.size()||state.elkFinished)return;
        try {
            var scope=state.scope;
            var page=evidence.search(scope.filter(),state.elkCursor,state.incident,scope.references(),scope.eventIds(),state.related);
            state.elk=page.content();state.elkPosition=0;state.elkCursor=page.nextCursor();
            state.sourceStatus=page.sourceStatus();state.elkFinished=page.nextCursor()==null;
        }catch(BadRequestException refused){
            if(!refused.getMessage().contains("RAW_VIEW_REFUSED"))throw refused;
            state.elkFinished=true;state.sourceStatus="RAW_REFUSED";state.elk=List.of();state.elkPosition=0;
        }
    }
    private List<Ref> references(String incident,LocalDateTime asOf,Set<String> types,LocalDateTime from,LocalDateTime to) {
        List<Ref> refs=new ArrayList<>();
        String range=from==null?"":" AND ngay_tao>=? AND ngay_tao<=?";
        Object[] args=from==null?new Object[]{incident,asOf}:new Object[]{incident,asOf,from,to};
        if(types.contains("NOTE"))refs.addAll(jdbc.query("SELECT id,ngay_tao FROM siem_incident_notes WHERE incident_id=? AND ngay_tao<=?"+range+" ORDER BY ngay_tao DESC,id LIMIT 10001",
                (r,n)->new Ref(r.getString(1),"NOTE",r.getTimestamp(2).toLocalDateTime()),args));
        if(types.contains("WORKFLOW"))refs.addAll(jdbc.query("SELECT id,ngay_tao FROM siem_incident_history WHERE incident_id=? AND ngay_tao<=? AND action<>'NOTE_ADDED'"+range+" ORDER BY ngay_tao DESC,id LIMIT 10001",
                (r,n)->new Ref(r.getString(1),"WORKFLOW",r.getTimestamp(2).toLocalDateTime()),args));
        if(types.contains("MODEL"))refs.addAll(jdbc.query("SELECT id,as_of FROM siem_postlogin_decisions WHERE incident_id=? AND created_at<=?"+(from==null?"":" AND as_of>=? AND as_of<=?")+" ORDER BY as_of DESC,id LIMIT 10001",
                (r,n)->new Ref(r.getString(1),"MODEL",r.getTimestamp(2).toLocalDateTime()),args));
        if(types.contains("MODEL"))refs.addAll(jdbc.query("SELECT id,as_of FROM siem_shadow_assessments WHERE incident_id=? AND created_at<=?"+(from==null?"":" AND as_of>=? AND as_of<=?")+" ORDER BY as_of DESC,id LIMIT 10001",
                (r,n)->new Ref(r.getString(1),"MODEL_SHADOW",r.getTimestamp(2).toLocalDateTime()),args));
        if(refs.size()>10000)throw new BadRequestException("Timeline has more than 10000 workflow references; narrow the investigation range.");
        refs.sort(ORDER);return List.copyOf(refs);
    }
    private Entry workflowEntry(Ref ref) {
        Map<String,Object> row=switch(ref.kind()) {
            case "NOTE" -> jdbc.queryForMap("SELECT author_user_id,content FROM siem_incident_notes WHERE id=?",ref.id());
            case "MODEL_SHADOW" -> jdbc.queryForMap("SELECT recommendation,context_class,raw_score,status,'PILOT_ONLY / SHADOW' AS mode,model_manifest_sha256 AS model_version FROM siem_shadow_assessments WHERE id=?",ref.id());
            case "MODEL" -> jdbc.queryForMap("SELECT decision,context_class,raw_score,normal_percentile,model_version,mode,outcome FROM siem_postlogin_decisions WHERE id=?",ref.id());
            default -> jdbc.queryForMap("SELECT actor_user_id,action,detail,previous_value,new_value FROM siem_incident_history WHERE id=?",ref.id());
        };
        return new Entry(ref.id(),ref.kind(),ref.at(),null,null,json.valueToTree(row));
    }
    private static LocalDateTime logTime(SiemEvidenceService.Item item) {
        try{return OffsetDateTime.parse(item.elkHit().path("_source").path("@timestamp").asText()).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();}
        catch(DateTimeException invalid){throw new BadRequestException("Evidence has an invalid timestamp.");}
    }
    private static Set<String> parseTypes(String input) {
        if(input==null||input.isBlank())return TYPES;
        Set<String> types=new TreeSet<>(List.of(input.split(",")));
        if(types.isEmpty()||!TYPES.containsAll(types))throw new BadRequestException("Unsupported timeline type.");
        return types;
    }
}
