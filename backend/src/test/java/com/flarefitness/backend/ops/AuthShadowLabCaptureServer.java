package com.flarefitness.backend.ops;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.service.siem.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Test-classpath only: controlled-clock raw observations over loopback HTTP -> actual backend extractors.
 * It has no database, authentication bypass, production route, SMTP transport or mutation endpoint.
 */
public final class AuthShadowLabCaptureServer {
    private static final ObjectMapper JSON=new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final Set<String> BASIC=Set.of("event_id","actor_user_id","target_user_id","event_type","action","outcome","event_timestamp","telemetry_contract_version","session_pseudonym","session_issued_at","http_status","endpoint_category","http_method","route_group","source_ip","user_agent_family");
    private static final Set<String> EXTRA=Set.of("challenge_reference","denial_reason","target_reference");
    private static final AtomicInteger REQUESTS=new AtomicInteger();
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Private lab token file required");
        Path tokenFile=Path.of(args[0]);byte[] token=Files.readAllBytes(tokenFile);
        if(token.length<32||token.length>128)throw new IllegalArgumentException("Bounded lab credential required");
        var server=HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(),0),8);
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.createContext("/capture",exchange->{
            byte[] response;int status;
            try {
                String supplied=exchange.getRequestHeaders().getFirst("X-Lab-Token");
                if(!exchange.getRequestMethod().equals("POST")||supplied==null||!MessageDigest.isEqual(token,supplied.getBytes(StandardCharsets.UTF_8)))throw new IllegalArgumentException("Forbidden lab request");
                byte[] body=exchange.getRequestBody().readNBytes(2*1024*1024+1);
                if(body.length>2*1024*1024||REQUESTS.incrementAndGet()>100010)throw new IllegalArgumentException("Lab capture budget exceeded");
                response=JSON.writeValueAsBytes(capture(JSON.readTree(body),token));status=200;
            }catch(Exception invalid){System.err.println("CAPTURE_REFUSED "+invalid.getClass().getSimpleName()+" at "+invalid.getStackTrace()[0].getClassName()+":"+invalid.getStackTrace()[0].getLineNumber());response="{\"status\":\"CAPTURE_REFUSED\"}".getBytes(StandardCharsets.UTF_8);status=400;}
            exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(status,response.length);
            try(var out=exchange.getResponseBody()){out.write(response);}exchange.close();
        });
        server.start();System.out.println(JSON.writeValueAsString(Map.of("port",server.getAddress().getPort(),"format","AUTH_CONTEXT_LAB_CAPTURE_V1","provenance","CONTROLLED_CLOCK_LAB","producer","REAL_JAVA_EXTRACTOR_LOOPBACK_HARNESS")));System.out.flush();
    }
    static Map<String,Object> capture(JsonNode frame,byte[] key)throws Exception {
        if(!frame.isObject()||frame.size()!=4||!frame.has("frame_id")||!frame.has("attempt")||!frame.has("context")||!frame.has("baseline_frames"))throw new IllegalArgumentException("Exact raw frame required; labels remain outside input");
        if(!frame.path("context").isArray()||frame.path("context").size()>1000)throw new IllegalArgumentException("Bounded context required");
        String frameId=text(frame,"frame_id",128);var current=event(frame.path("attempt"),frameId,key);
        var base=frame.deepCopy();var baseContext=JSON.createArrayNode();List<PostloginShadowFeatures.Observation> context=new ArrayList<>();
        for(JsonNode raw:frame.path("context")){
            var observation=new PostloginShadowFeatures.Observation(event(raw,frameId,key),optional(raw,"challenge_reference",64));
            if(!observation.event().at().isBefore(current.at()))throw new IllegalArgumentException("No current/future outcome may enter context");
            context.add(observation);
            if(!"AUTH_INVESTIGATION".equals(observation.event().type())&&(Objects.equals(current.actor(),observation.event().actor())||observation.event().actor()==null&&Objects.equals(current.actor(),observation.event().target())))baseContext.add(basic(raw));
        }
        ((ObjectNode)base).set("context",baseContext);((ObjectNode)base).set("attempt",basic(frame.path("attempt")));
        var prefix=PostLoginFeatureExport.transformRisk(base,new UebaFeatureExport.History());
        List<Object> features=new ArrayList<>(),names=new ArrayList<>();
        for(String field:List.of("baseline_features","postlogin_features","rolling_features"))features.addAll((List<?>)prefix.get(field));
        for(String field:List.of("baseline_feature_names","postlogin_feature_names","rolling_feature_names"))names.addAll((List<?>)prefix.get(field));
        var snapshot=new LinkedHashMap<String,Object>();snapshot.put("snapshot_id",frameId);snapshot.put("evaluation_unit","SENSITIVE_ACTION_ATTEMPT");snapshot.put("feature_schema_version",6);snapshot.put("feature_names",names);snapshot.put("features",features);
        snapshot.put("as_of",text(frame.path("attempt"),"event_timestamp",40));snapshot.put("baseline_established",prefix.get("baseline_established"));snapshot.put("trusted_window_count",prefix.get("trusted_window_count"));
        var extra=PostloginShadowFeatures.build(snapshot,current,context,true);
        return Map.of("status",extra.covered()?"OBSERVED":"UNDETERMINED","reason",extra.reason(),"snapshot",extra.packet(),"source_event_id",current.id(),"source_context_count",context.size(),"before_current_outcome",true,"producer","REAL_JAVA_EXTRACTOR_LOOPBACK_HARNESS");
    }
    private static ObjectNode basic(JsonNode raw){ObjectNode copy=((ObjectNode)raw).deepCopy();var remove=new ArrayList<String>();copy.fieldNames().forEachRemaining(k->{if(!BASIC.contains(k))remove.add(k);});copy.remove(remove);return copy;}
    private static AuthInvestigationRules.Event event(JsonNode raw,String frame,byte[] key)throws Exception {
        if(!raw.isObject())throw new IllegalArgumentException("Observed event required");raw.fieldNames().forEachRemaining(name->{if(!BASIC.contains(name)&&!EXTRA.contains(name))throw new IllegalArgumentException("Unknown observation field");});
        String id=text(raw,"event_id",128),target=optional(raw,"target_user_id",64),reference=optional(raw,"target_reference",64);
        String fingerprint=null;
        if(reference!=null){var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(key,"HmacSHA256"));fingerprint=HexFormat.of().formatHex(mac.doFinal(("lab-target-v1\0"+reference).getBytes(StandardCharsets.UTF_8)));}
        String keyId=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key)).substring(0,16);
        String type=text(raw,"event_type",48),action=text(raw,"action",80);
        String session=optional(raw,"session_pseudonym",64),issued=optional(raw,"session_issued_at",40);
        if((session==null)!=(issued==null)||session!=null&&(!session.matches("[a-f0-9]{64}")||Instant.parse(issued).isAfter(Instant.parse(text(raw,"event_timestamp",40)))))throw new IllegalArgumentException("Observed session chronology invalid");
        return new AuthInvestigationRules.Event(id,UUID.nameUUIDFromBytes((frame+"|"+id).getBytes(StandardCharsets.UTF_8)).toString(),LocalDateTime.ofInstant(Instant.parse(text(raw,"event_timestamp",40)),ZoneOffset.UTC),type,action,text(raw,"outcome",16),optional(raw,"actor_user_id",64),target,fingerprint,keyId,optional(raw,"source_ip",64),optional(raw,"user_agent_family",32),optional(raw,"session_pseudonym",64),"SENSITIVE_ACTION_ATTEMPT".equals(type)?action:optional(raw,"route_group",64),optional(raw,"denial_reason",48));
    }
    private static String optional(JsonNode object,String key,int max){return object.hasNonNull(key)?text(object,key,max):null;}
    private static String text(JsonNode object,String key,int max){var value=object.get(key);if(value==null||!value.isTextual()||value.asText().isBlank()||value.asText().length()>max)throw new IllegalArgumentException("Bounded observation field required");return value.asText();}
}
