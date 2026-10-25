package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/** A bounded, allowlisted Discover reader. Native hits never pass through DTO/map conversion. */
@Service
public class SiemEvidenceService {
    private static final Map<String,String> STREAMS = Map.of(
            "nginx.access", "logs-nginx.access-lab", "flare.security", "logs-flare.security-lab",
            "flare.prevention", "logs-flare.prevention-lab");
    private final SiemElasticGateway elastic;
    private final ObjectMapper mapper;
    private final Map<String, Cursor> cursors = new ConcurrentHashMap<>();
    private final java.util.concurrent.Semaphore searchSlots=new java.util.concurrent.Semaphore(4);
    public SiemEvidenceService(SiemElasticGateway elastic, ObjectMapper mapper) {
        this.elastic = elastic; this.mapper = mapper;
    }
    public record Filter(LocalDateTime from, LocalDateTime to, String dataset, String traceId,
                         String ip, String accountId, int size) { }
    public record Association(String incidentId, String matchType, String provenance) { }
    public record Item(JsonNode elkHit, Association association) { }
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Page(List<Item> content, String nextCursor, String sourceStatus) { }
    private record Cursor(Filter filter, String incident, String pit, JsonNode sort, long expires, String owner, String scope) { }

    public Page search(Filter filter, String token, String incidentId, Set<String> directReferences) {
        return search(filter,token,incidentId,directReferences,Set.of());
    }
    public Page search(Filter filter,String token,String incidentId,Set<String> directReferences,Set<String> directEventIds) {
        return search(filter,token,incidentId,directReferences,directEventIds,directReferences.isEmpty());
    }
    public Page search(Filter filter,String token,String incidentId,Set<String> directReferences,Set<String> directEventIds,boolean includeRelated) {
        validate(filter);
        String scope=new TreeSet<>(directReferences)+"|"+new TreeSet<>(directEventIds)+"|"+includeRelated;
        if (!elastic.isEnabled()) return new Page(List.of(), null, "DISABLED");
        if(!searchSlots.tryAcquire())return new Page(List.of(),null,"BUSY");
        String pit = null;
        try {
            var body = mapper.createObjectNode();
            body.put("size", filter.size());
            if (token != null && !token.isBlank()) {
                Cursor cursor = cursors.get(token);
                if (cursor == null || cursor.expires < System.currentTimeMillis()
                        || !cursor.filter.equals(filter) || !Objects.equals(cursor.incident, incidentId)
                        || !cursor.owner.equals(cursorOwner()) || !cursor.scope.equals(scope))
                    throw new BadRequestException("Cursor expired or does not match the filters.");
                pit = cursor.pit;
                body.set("search_after", cursor.sort);
            } else {
                cursors.entrySet().removeIf(e -> {
                    if(e.getValue().expires >= System.currentTimeMillis())return false;
                    elastic.closePointInTime(e.getValue().pit);return true;
                });
                if (cursors.size() >= 32) throw new ServiceUnavailableException("Too many evidence cursors.");
                String indices = filter.dataset == null || filter.dataset.isBlank()
                        ? String.join(",", new TreeSet<>(STREAMS.values())) : STREAMS.get(filter.dataset);
                pit = elastic.request("POST", "/" + indices + "/_pit?keep_alive=2m", null,
                        Duration.ofSeconds(8)).path("id").asText();
                if (pit.isBlank()) throw new ServiceUnavailableException("Evidence snapshot unavailable.");
            }
            body.set("pit", mapper.valueToTree(Map.of("id", pit, "keep_alive", "2m")));
            body.set("sort", mapper.valueToTree(List.of(Map.of("@timestamp", Map.of("order", "desc",
                    "format", "strict_date_optional_time_nanos")), Map.of("_shard_doc", "desc"))));
            body.set("query", mapper.valueToTree(query(filter,directReferences,directEventIds,includeRelated)));
            JsonNode response = elastic.request("POST", "/_search", body.toString(), Duration.ofSeconds(8));
            pit = response.path("pit_id").asText(pit);
            List<Item> content = new ArrayList<>();
            JsonNode lastSort = null;
            for (JsonNode hit : response.path("hits").path("hits")) {
                requireSafeHit(hit);
                String ref = hit.path("_index").asText() + "\n" + hit.path("_id").asText();
                boolean referenced=directReferences.contains(ref);
                boolean linked=directEventIds.contains(hit.path("_source").path("event").path("id").asText());
                content.add(new Item(hit, incidentId == null ? null : new Association(incidentId,
                        referenced || linked ? "DIRECT" : "RELATED",
                        referenced ? "EVENT_REFERENCE" : linked ? "SERVER_VERIFIED_EVENT_ID" : "IP_ACCOUNT_TIME_WINDOW")));
                lastSort = hit.path("sort");
            }
            String next = null;
            if (content.size() == filter.size() && lastSort != null && lastSort.isArray()) {
                next = UUID.randomUUID().toString();
                cursors.put(next, new Cursor(filter, incidentId, pit, lastSort, System.currentTimeMillis() + 120_000,cursorOwner(),scope));
            } else elastic.closePointInTime(pit);
            if(token!=null)cursors.remove(token);
            return new Page(content, next, "AVAILABLE");
        } catch (ServiceUnavailableException failure) {
            if(pit!=null)elastic.closePointInTime(pit);
            if(token!=null)cursors.remove(token);
            return new Page(List.of(), null, "UNAVAILABLE");
        } catch (RuntimeException failure) {
            if (pit != null) elastic.closePointInTime(pit);
            throw failure;
        } finally {searchSlots.release();}
    }
    /** Identity binds opaque cursors to the authenticated session without retaining its token. */
    static String cursorOwner() {
        var authentication=org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        String owner=authentication==null?"NON_WEB_TEST":authentication.getName();
        var attributes=org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        if(attributes instanceof org.springframework.web.context.request.ServletRequestAttributes servlet) {
            Object token=servlet.getRequest().getAttribute(com.flarefitness.backend.security.JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE);
            if(token instanceof String value)try {
                owner+="|"+HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            } catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
        }
        return owner;
    }
    static Object query(Filter filter,Set<String> references,Set<String> eventIds,boolean includeRelated) {
        var time=Map.of("range",Map.of("@timestamp",Map.of("gte",filter.from.toInstant(ZoneOffset.UTC).toString(),"lte",filter.to.toInstant(ZoneOffset.UTC).toString())));
        List<Object> context=new ArrayList<>();term(context,"trace.id",filter.traceId);term(context,"source.ip",filter.ip);
        if(filter.accountId!=null&&!filter.accountId.isBlank())context.add(Map.of("bool",Map.of("minimum_should_match",1,"should",List.of(
                Map.of("term",Map.of("user.id",filter.accountId)),Map.of("term",Map.of("target.user.id",filter.accountId))))));
        List<Object> direct=new ArrayList<>();
        for(String ref:references){int separator=ref.indexOf('\n');if(separator>0)direct.add(Map.of("bool",Map.of("filter",List.of(
                Map.of("term",Map.of("_index",ref.substring(0,separator))),Map.of("ids",Map.of("values",List.of(ref.substring(separator+1))))))));}
        if(!eventIds.isEmpty())direct.add(Map.of("terms",Map.of("event.id",new TreeSet<>(eventIds))));
        Object relation;
        if(direct.isEmpty())relation=context.isEmpty()?Map.of("match_all",Map.of()):Map.of("bool",Map.of("filter",context));
        else {
            if(includeRelated&&!context.isEmpty())direct.add(Map.of("bool",Map.of("filter",context)));
            relation=Map.of("bool",Map.of("minimum_should_match",1,"should",direct));
        }
        return Map.of("bool",Map.of("filter",List.of(time,relation)));
    }
    public record ObservedValue(String value,String index,String id) { }
    public record ValueGroup(List<ObservedValue> values,boolean hasMore) { }
    public record Aggregate(Map<String,ValueGroup> groups,String sourceStatus,LocalDateTime firstObservedAt) {
        public Aggregate(Map<String,ValueGroup> groups,String sourceStatus){this(groups,sourceStatus,null);}
    }
    /** Controlled runtime fields support both historical text and new ECS mappings, without rewriting either. */
    public Aggregate aggregate(Filter filter,Set<String> refs,Set<String> ids) {
        validate(filter);if(!elastic.isEnabled())return new Aggregate(Map.of(),"DISABLED");
        var fields=List.of("source.ip","source.port","destination.ip","destination.port","server.ip","server.port","user.id","user.name","target.user.id","session.pseudonym","observer.type","event.action","event.outcome","http.response.status_code","event.reason","error.message","message","flare.detection.type","url.path");
        var runtime=new LinkedHashMap<String,Object>();var aggs=new LinkedHashMap<String,Object>();
        for(int i=0;i<fields.size();i++){
            String key="investigation_"+i;String field=fields.get(i);
            runtime.put(key,Map.of("type","keyword","script",Map.of("source","def v=params._source; if(v.containsKey(params.key)){v=v[params.key];}else{for(def p:params.path){if(!(v instanceof Map)||!v.containsKey(p))return;v=v[p];}} if(v==null)return; if(v instanceof List){for(def x:v){if(x!=null)emit(x.toString());}}else emit(v.toString());","params",Map.of("key",field,"path",List.of(field.split("\\."))))));
            aggs.put(key,Map.of("terms",Map.of("field",key,"size",21),"aggs",Map.of("reference",Map.of("top_hits",Map.of("size",1,"_source",false)))));
        }
        aggs.put("first_observed_at",Map.of("min",Map.of("field","@timestamp","format","strict_date_time")));
        try {
            String streams=String.join(",",new TreeSet<>(STREAMS.values()));
            var response=elastic.request("POST","/"+streams+"/_search",mapper.writeValueAsString(Map.of("size",0,"timeout","5s","query",query(filter,refs,ids,false),"runtime_mappings",runtime,"aggs",aggs)),Duration.ofSeconds(8));
            var groups=new LinkedHashMap<String,ValueGroup>();
            for(int i=0;i<fields.size();i++){
                var buckets=response.path("aggregations").path("investigation_"+i).path("buckets");List<ObservedValue> values=new ArrayList<>();
                for(JsonNode bucket:buckets){if(values.size()==20)break;var hit=bucket.path("reference").path("hits").path("hits").path(0);
                    values.add(new ObservedValue(bucket.path("key").asText(),hit.path("_index").asText(),hit.path("_id").asText()));}
                groups.put(fields.get(i),new ValueGroup(List.copyOf(values),buckets.size()>20));
            }
            String status=response.path("timed_out").asBoolean()||response.path("_shards").path("failed").asInt()>0?"PARTIAL":"AVAILABLE";
            return new Aggregate(groups,status,firstObserved(response.path("aggregations"),status));
        }catch(com.fasterxml.jackson.core.JsonProcessingException impossible){throw new IllegalStateException(impossible);}
        catch(ServiceUnavailableException unavailable){return new Aggregate(Map.of(),"UNAVAILABLE");}
    }
    /** One bounded Elasticsearch query enriches an entire queue page, not one request per incident. */
    public Map<String,Aggregate> aggregateBatch(Map<String,SiemWorkspaceService.EvidenceScope> scopes) {
        if(scopes.size()>100)throw new BadRequestException("At most100 queue summaries allowed.");
        var result=new LinkedHashMap<String,Aggregate>();var filters=new LinkedHashMap<String,Object>();
        scopes.forEach((id,scope)->{
            if(scope.fixture()||scope.references().isEmpty()&&scope.eventIds().isEmpty())result.put(id,new Aggregate(Map.of(),"NO_DETECTION_LOG"));
            else {validate(scope.filter());filters.put(id,query(scope.filter(),scope.references(),scope.eventIds(),false));}
        });
        if(filters.isEmpty())return result;
        if(!elastic.isEnabled()){filters.keySet().forEach(id->result.put(id,new Aggregate(Map.of(),"DISABLED")));return result;}
        var fields=List.of("source.ip","destination.ip","server.ip","user.id","user.name","target.user.id","flare.detection.type","url.path");
        var runtime=new LinkedHashMap<String,Object>();var aggs=new LinkedHashMap<String,Object>();
        for(int i=0;i<fields.size();i++){
            String key="queue_"+i,field=fields.get(i);
            runtime.put(key,Map.of("type","keyword","script",Map.of("source","def v=params._source;if(v.containsKey(params.key)){v=v[params.key];}else{for(def p:params.path){if(!(v instanceof Map)||!v.containsKey(p))return;v=v[p];}}if(v==null)return;if(v instanceof List){for(def x:v){if(x!=null)emit(x.toString());}}else emit(v.toString());","params",Map.of("key",field,"path",List.of(field.split("\\."))))));
            aggs.put(key,Map.of("terms",Map.of("field",key,"size",3),"aggs",Map.of("reference",Map.of("top_hits",Map.of("size",1,"_source",false)))));
        }
        aggs.put("first_observed_at",Map.of("min",Map.of("field","@timestamp","format","strict_date_time")));
        try {
            var body=Map.of("size",0,"timeout","5s","runtime_mappings",runtime,"query",Map.of("bool",Map.of("minimum_should_match",1,"should",new ArrayList<>(filters.values()))),
                "aggs",Map.of("incidents",Map.of("filters",Map.of("filters",filters),"aggs",aggs)));
            var response=elastic.request("POST","/"+String.join(",",new TreeSet<>(STREAMS.values()))+"/_search",mapper.writeValueAsString(body),Duration.ofSeconds(8));
            String status=response.path("timed_out").asBoolean()||response.path("_shards").path("failed").asInt()>0?"PARTIAL":"AVAILABLE";
            for(String id:filters.keySet()){
                var groups=new LinkedHashMap<String,ValueGroup>();var bucket=response.path("aggregations").path("incidents").path("buckets").path(id);
                for(int i=0;i<fields.size();i++){
                    var terms=bucket.path("queue_"+i).path("buckets");List<ObservedValue> values=new ArrayList<>();
                    for(JsonNode term:terms){if(values.size()==2)break;var hit=term.path("reference").path("hits").path("hits").path(0);values.add(new ObservedValue(term.path("key").asText(),hit.path("_index").asText(),hit.path("_id").asText()));}
                    groups.put(fields.get(i),new ValueGroup(List.copyOf(values),terms.size()>2));
                }
                result.put(id,new Aggregate(groups,status,firstObserved(bucket,status)));
            }
        }catch(com.fasterxml.jackson.core.JsonProcessingException impossible){throw new IllegalStateException(impossible);}
        catch(ServiceUnavailableException unavailable){filters.keySet().forEach(id->result.put(id,new Aggregate(Map.of(),"UNAVAILABLE")));}
        return Map.copyOf(result);
    }
    /** Earliest retained direct evidence in this bounded query; partial searches cannot establish the minimum. */
    private static LocalDateTime firstObserved(JsonNode aggregations,String status) {
        JsonNode value=aggregations.path("first_observed_at");
        if(!"AVAILABLE".equals(status)||!value.path("value").isNumber()||!value.path("value_as_string").isTextual())return null;
        try{return java.time.OffsetDateTime.parse(value.path("value_as_string").asText()).withOffsetSameInstant(java.time.ZoneOffset.UTC).toLocalDateTime();}
        catch(java.time.DateTimeException invalid){return null;}
    }
    private static void term(List<Object> filters, String field, String value) {
        if (value != null && !value.isBlank()) filters.add(Map.of("term", Map.of(field, value)));
    }
    private static void validate(Filter f) {
        if (f.from == null || f.to == null || !f.from.isBefore(f.to)
                || Duration.between(f.from, f.to).compareTo(Duration.ofDays(31)) > 0
                || f.size < 1 || f.size > 100
                || (f.dataset != null && !f.dataset.isBlank() && !STREAMS.containsKey(f.dataset)))
            throw new BadRequestException("Invalid evidence time range, dataset or page size.");
        for (String value : new String[]{f.traceId, f.ip, f.accountId})
            if (value != null && (value.length() > 128 || value.chars().anyMatch(Character::isISOControl)))
                throw new BadRequestException("Invalid evidence filter.");
    }
    public JsonNode fetch(String index, String id) {
        if (!allowedIndex(index) || id == null || !id.matches("[A-Za-z0-9_-]{1,256}"))
            throw new BadRequestException("Invalid evidence reference.");
        JsonNode hit = elastic.request("GET", "/" + index + "/_doc/" + id, null, Duration.ofSeconds(8));
        requireSafeHit(hit); return hit;
    }
    static boolean allowedIndex(String index) {
        return index != null && STREAMS.values().stream().anyMatch(s -> index.equals(s)
                || index.matches("\\.ds-" + java.util.regex.Pattern.quote(s) + "-\\d{4}\\.\\d{2}\\.\\d{2}-\\d{6}"));
    }
    static void requireSafeHit(JsonNode hit) {
        if (!allowedIndex(hit.path("_index").asText()) || !hit.path("_source").isObject())
            throw new BadRequestException("Invalid evidence document.");
        checkFields(hit.path("_source"), "");
        if (hit.has("fields")) checkFields(hit.path("fields"), "");
    }
    private static void checkFields(JsonNode node, String path) {
        if (node.isArray()) { node.forEach(n -> checkFields(n, path)); return; }
        if (!node.isObject()) return;
        node.fields().forEachRemaining(entry -> {
            String key = (path + "." + entry.getKey()).toLowerCase(Locale.ROOT).replace('-', '_');
            if (key.matches(".*(?:^|[._])(password|passwd|authorization|cookie|set_cookie|access_token|refresh_token|csrf_token|api_key|token|credentials|credential|secret|private_key|otp)(?:[._].*|$)")
                    || key.contains("request.body") || key.contains("request_body"))
                throw new BadRequestException("RAW_VIEW_REFUSED: sensitive field outside the source contract.");
            checkFields(entry.getValue(), key);
        });
    }
}
