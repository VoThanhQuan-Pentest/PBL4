package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SiemElasticGateway {
    private static final String ACCESS_INDEX = "logs-nginx.access-lab";
    private static final String SECURITY_INDEX = "logs-flare.security-lab";
    private static final String PREVENTION_INDEX = "logs-flare.prevention-lab";
    private static final String ALERT_INDEX = ".alerts-security.alerts-flare-lab";
    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final String baseUrl;
    private final String username;
    private final Path passwordFile;
    private final Path caFile;
    private volatile HttpClient httpClient;

    public SiemElasticGateway(
            ObjectMapper objectMapper,
            @Value("${siem.enabled:false}") boolean enabled,
            @Value("${siem.elasticsearch.url:https://elasticsearch:9200}") String baseUrl,
            @Value("${siem.elasticsearch.username:flare_siem_reader}") String username,
            @Value("${siem.elasticsearch.password-file:/run/secrets/siem_elasticsearch_password}") String passwordFile,
            @Value("${siem.elasticsearch.ca-file:/run/secrets/siem_elasticsearch_ca}") String caFile
    ) {
        this.objectMapper = objectMapper.copy()
                .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
                .setNodeFactory(com.fasterxml.jackson.databind.node.JsonNodeFactory.withExactBigDecimals(true));
        this.enabled = enabled;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.username = username;
        this.passwordFile = Path.of(passwordFile);
        this.caFile = Path.of(caFile);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isAvailable() {
        if (!enabled) return false;
        try {
            // The least-privilege reader intentionally has no cluster-level
            // permission for GET /. Probe an index endpoint it can read.
            request("GET", "/" + ACCESS_INDEX + "/_count", null, Duration.ofSeconds(2));
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    public List<SiemDtos.ElasticDocument> searchLogs(LocalDateTime from, LocalDateTime to, int size) {
        validateRange(from, to);
        int safeSize = Math.max(1, Math.min(100, size));
        String body;
        try {
            body = objectMapper.writeValueAsString(Map.of(
                    "size", safeSize,
                    "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                    "query", Map.of("range", Map.of("@timestamp", range(from, to)))));
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot build Elasticsearch query", exception);
        }
        return parseHits(request("POST", "/" + ACCESS_INDEX + "/_search", body, Duration.ofSeconds(8)));
    }

    public List<SiemDtos.ElasticDocument> searchIncidentLogs(
            String sourceIp, LocalDateTime from, LocalDateTime to, int size) {
        if (sourceIp == null || sourceIp.isBlank()) return List.of();
        validateRange(from, to);
        try {
            String body = objectMapper.writeValueAsString(Map.of(
                    "size", Math.max(1, Math.min(100, size)),
                    "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                    "query", Map.of("bool", Map.of("filter", List.of(
                            Map.of("term", Map.of("source.ip", sourceIp)),
                            Map.of("range", Map.of("@timestamp", range(from, to))))))));
            return parseHits(request("POST", "/" + ACCESS_INDEX + "/_search", body, Duration.ofSeconds(8)));
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot build Elasticsearch query", exception);
        }
    }

    public List<SiemDtos.ElasticDocument> searchIncidentSecurityDocuments(
            String accountId, String sourceIp, LocalDateTime from, LocalDateTime to, int size) {
        if (accountId == null || accountId.isBlank()) return List.of();
        validateRange(from, to);
        try {
            String body = securityQuery(accountId, sourceIp, from, to, size);
            return parseHits(request("POST", "/" + SECURITY_INDEX + "/_search", body, Duration.ofSeconds(8)));
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot build account security-log query", exception);
        }
    }

    public List<SiemDtos.ElasticDocument> searchIncidentPreventionDocuments(
            String sourceIp, LocalDateTime from, LocalDateTime to, int size) {
        if (sourceIp == null || sourceIp.isBlank()) return List.of();
        validateRange(from, to);
        try {
            String body = objectMapper.writeValueAsString(Map.of(
                    "size", Math.max(1, Math.min(100, size)),
                    "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                    "_source", List.of("@timestamp", "event.id", "event.type", "event.action",
                            "trace.id", "source.ip", "source.geo.country_name",
                            "source.geo.city_name", "source.as.number",
                            "flare.prevention.rule_id", "flare.prevention.policy_version"),
                    "query", Map.of("bool", Map.of("filter", List.of(
                            Map.of("term", Map.of("source.ip", sourceIp)),
                            Map.of("range", Map.of("@timestamp", range(from, to))))))));
            return parseHits(request("POST", "/" + PREVENTION_INDEX + "/_search", body,
                    Duration.ofSeconds(8)));
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot build prevention evidence query", exception);
        }
    }

    public List<PreventionEvent> recentPreventionEvents(LocalDateTime since) {
        if (since == null) throw new BadRequestException("Prevention cursor is required.");
        List<PreventionEvent> events = new ArrayList<>();
        List<Object> searchAfter = null;
        try {
            for (int page = 0; page < 10; page++) {
                var query = objectMapper.createObjectNode();
                query.put("size", 1000);
                query.set("sort", objectMapper.valueToTree(List.of(
                        Map.of("@timestamp", Map.of("order", "asc")),
                        Map.of("event.id", Map.of("order", "asc")))));
                query.set("_source", objectMapper.valueToTree(List.of(
                        "@timestamp", "event.id", "event.type", "event.action",
                        "trace.id", "source.ip", "flare.prevention.rule_id",
                        "flare.prevention.policy_version", "flare.prevention.provenance")));
                query.set("query", objectMapper.valueToTree(Map.of("range", Map.of(
                        "@timestamp", Map.of("gte", since.toInstant(ZoneOffset.UTC).toString())))));
                if (searchAfter != null) query.set("search_after", objectMapper.valueToTree(searchAfter));
                JsonNode root = request("POST", "/" + PREVENTION_INDEX + "/_search",
                        objectMapper.writeValueAsString(query), Duration.ofSeconds(8));
                JsonNode hits = root.path("hits").path("hits");
                if (!hits.isArray() || hits.isEmpty()) break;
                for (JsonNode hit : hits) {
                    JsonNode source = hit.path("_source");
                    String id = source.path("event").path("id").asText();
                    String timestamp = source.path("@timestamp").asText();
                    if (id.isBlank() || timestamp.isBlank()) continue;
                    events.add(new PreventionEvent(
                            id, source.path("trace").path("id").asText(),
                            source.path("source").path("ip").asText(),
                            source.path("event").path("type").asText(),
                            source.path("flare").path("prevention").path("rule_id").asText(null),
                            source.path("flare").path("prevention").path("policy_version").asLong(),
                            source.path("event").path("action").asText(),
                            source.path("flare").path("prevention").path("count").asInt(1),
                            OffsetDateTime.parse(timestamp).atZoneSameInstant(ZoneOffset.UTC).toLocalDateTime(),
                            source.path("flare").path("prevention").path("provenance").asText("UNVERIFIED")));
                    searchAfter = objectMapper.convertValue(hit.path("sort"), List.class);
                }
                if (hits.size() < 1000) break;
            }
            return events;
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("Prevention events are temporarily unavailable.");
        }
    }

    public record PreventionEvent(String id, String traceId, String sourceIp,
                                  String type, String ruleId, long policyVersion,
                                  String action, int count, LocalDateTime occurredAt, String provenance) {
        public PreventionEvent(String id,String traceId,String sourceIp,String type,String ruleId,long policyVersion,
                String action,int count,LocalDateTime occurredAt) {
            this(id,traceId,sourceIp,type,ruleId,policyVersion,action,count,occurredAt,"UNVERIFIED");
        }
    }

    public List<IpScanCandidate> endpointScanCandidates(LocalDateTime since, LocalDateTime to) {
        validateRange(since, to);
        try {
            Map<String, Object> byIp = Map.of(
                    "terms", Map.of("field", "source.ip", "size", 100, "min_doc_count", 20),
                    "aggs", Map.of(
                            "paths", Map.of("cardinality", Map.of(
                                    "field", "url.path", "precision_threshold", 1000)),
                            "errors", Map.of("filter", Map.of("terms", Map.of(
                                    "http.response.status_code", List.of(401, 403, 404))))));
            String body = objectMapper.writeValueAsString(Map.of(
                    "size", 0,
                    "query", Map.of("range", Map.of("@timestamp", range(since, to))),
                    "aggs", Map.of("by_ip", byIp)));
            JsonNode root = request("POST", "/" + ACCESS_INDEX + "/_search", body, Duration.ofSeconds(8));
            List<IpScanCandidate> candidates = new ArrayList<>();
            for (JsonNode bucket : root.path("aggregations").path("by_ip").path("buckets")) {
                int paths = bucket.path("paths").path("value").asInt();
                long errors = bucket.path("errors").path("doc_count").asLong();
                if (paths >= 20 && errors >= 10) {
                    candidates.add(new IpScanCandidate(bucket.path("key").asText(),
                            paths, errors));
                }
            }
            return candidates;
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("Endpoint scan aggregation unavailable.");
        }
    }

    public record IpScanCandidate(String sourceIp, int distinctPaths, long errors) { }

    String securityQuery(String accountId, String sourceIp,
                         LocalDateTime from, LocalDateTime to, int size) throws Exception {
        List<Map<String, Object>> filters = new ArrayList<>();
        filters.add(Map.of("range", Map.of("@timestamp", range(from, to))));
        if (sourceIp != null && !sourceIp.isBlank()) {
            filters.add(Map.of("term", Map.of("source.ip", sourceIp)));
        }
        Map<String, Object> query = Map.of("bool", Map.of(
                "filter", filters,
                "should", List.of(Map.of("term", Map.of("user.id", accountId)),
                        Map.of("term", Map.of("target.user.id", accountId))),
                "minimum_should_match", 1));
        return objectMapper.writeValueAsString(Map.of(
                "size", Math.max(1, Math.min(100, size)),
                "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                "_source", List.of("@timestamp", "event.id", "event.action", "event.outcome",
                        "user.id", "target.user.id", "source.ip", "source.geo.country_name",
                        "source.geo.city_name", "source.geo.country_iso_code", "source.as.number",
                        "flare.source_ip_scope", "flare.synthetic", "flare.demo_label",
                        "http.response.status_code"),
                "query", query));
    }

    public record GeoSummary(String sourceStatus,long events,long geolocated,long publicWithoutGeo,
            Map<String,Long> scopes,List<SiemDtos.GeoBucket> locations) { }
    public GeoSummary geoSummary(LocalDateTime from,LocalDateTime to) {
        validateRange(from,to);
        if(!enabled)return new GeoSummary("DISABLED",0,0,0,Map.of(),List.of());
        try {
            String body=objectMapper.writeValueAsString(Map.of("size",0,"track_total_hits",true,
                "query",Map.of("range",Map.of("@timestamp",range(from,to))),"aggs",Map.of(
                "geolocated",Map.of("filter",Map.of("exists",Map.of("field","source.geo.location"))),
                "public_missing",Map.of("filter",Map.of("bool",Map.of(
                    "filter",List.of(Map.of("exists",Map.of("field","source.ip"))),
                    "must_not",List.of(Map.of("exists",Map.of("field","flare.source_ip_scope")),Map.of("exists",Map.of("field","source.geo.location")))))),
                "scopes",Map.of("terms",Map.of("field","flare.source_ip_scope","size",10)))));
            JsonNode root=request("POST","/"+ACCESS_INDEX+"/_search",body,Duration.ofSeconds(8));
            Map<String,Long> scopes=new java.util.LinkedHashMap<>();
            for(JsonNode bucket:root.path("aggregations").path("scopes").path("buckets"))scopes.put(bucket.path("key").asText(),bucket.path("doc_count").asLong());
            return new GeoSummary("AVAILABLE",root.path("hits").path("total").path("value").asLong(),
                root.path("aggregations").path("geolocated").path("doc_count").asLong(),
                root.path("aggregations").path("public_missing").path("doc_count").asLong(),scopes,geo(from,to));
        }catch(ServiceUnavailableException e){return new GeoSummary("UNAVAILABLE",0,0,0,Map.of(),List.of());}
        catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Cannot encode geographic summary.",e);}
    }

    public List<SiemDtos.GeoBucket> geo(LocalDateTime from, LocalDateTime to) {
        validateRange(from, to);
        try {
            Map<String, Object> filtered = Map.of(
                    "filter", Map.of("bool", Map.of("filter", List.of(
                            Map.of("range", Map.of("@timestamp", range(from, to))),
                            Map.of("exists", Map.of("field", "source.geo.location"))))),
                    "aggs", Map.of("countries", Map.of(
                            "terms", Map.of("field", "source.geo.country_iso_code", "size", 50),
                            "aggs", Map.of(
                                    "country_name", Map.of("top_hits", Map.of("size", 1, "_source", "source.geo.country_name")),
                                    "location", Map.of("geo_centroid", Map.of("field", "source.geo.location"))))));
            String body = objectMapper.writeValueAsString(Map.of("size", 0, "aggs", Map.of("filtered", filtered)));
            JsonNode root = request("POST", "/" + ACCESS_INDEX + "/_search", body, Duration.ofSeconds(8));
            List<SiemDtos.GeoBucket> result = new ArrayList<>();
            for (JsonNode bucket : root.path("aggregations").path("filtered").path("countries").path("buckets")) {
                JsonNode source = bucket.path("country_name").path("hits").path("hits").path(0).path("_source");
                JsonNode location = bucket.path("location").path("location");
                result.add(new SiemDtos.GeoBucket(
                        bucket.path("key").asText(),
                        source.path("source").path("geo").path("country_name").asText(bucket.path("key").asText()),
                        location.path("lat").asDouble(),
                        location.path("lon").asDouble(),
                        bucket.path("doc_count").asLong()));
            }
            return result;
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot parse Elasticsearch GeoIP response", exception);
        }
    }

    public String openAlertPointInTime() {
        return request("POST", "/" + ALERT_INDEX + "/_pit?keep_alive=2m", null, Duration.ofSeconds(8))
                .path("id").asText();
    }

    public AlertPage fetchAlertPage(String pitId, LocalDateTime since, List<Object> searchAfter, int size) {
        try {
            var body = objectMapper.createObjectNode();
            body.put("size", Math.max(1, Math.min(500, size)));
            body.set("pit", objectMapper.valueToTree(Map.of("id", pitId, "keep_alive", "2m")));
            body.set("sort", objectMapper.valueToTree(List.of(
                    Map.of("@timestamp", Map.of("order", "asc", "format", "strict_date_optional_time_nanos")),
                    Map.of("_shard_doc", "asc"))));
            body.set("query", objectMapper.valueToTree(Map.of(
                    "range", Map.of("@timestamp", Map.of(
                            "gte", since.toInstant(ZoneOffset.UTC).toString(),
                            "lte", "now")))));
            if (searchAfter != null && !searchAfter.isEmpty()) {
                body.set("search_after", objectMapper.valueToTree(searchAfter));
            }
            JsonNode root = request("POST", "/_search", objectMapper.writeValueAsString(body), Duration.ofSeconds(12));
            List<ElasticAlert> alerts = new ArrayList<>();
            List<Object> nextSort = List.of();
            for (JsonNode hit : root.path("hits").path("hits")) {
                alerts.add(parseAlert(hit));
                nextSort = objectMapper.convertValue(hit.path("sort"), List.class);
            }
            return new AlertPage(alerts, nextSort);
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot parse Elasticsearch alert page", exception);
        }
    }

    public void closePointInTime(String pitId) {
        if (pitId == null || pitId.isBlank()) return;
        try {
            request("DELETE", "/_pit", objectMapper.writeValueAsString(Map.of("id", pitId)), Duration.ofSeconds(5));
        } catch (Exception ignored) {
            // PIT expiration is safe; the next cycle opens a fresh snapshot.
        }
    }

    private Map<String, String> range(LocalDateTime from, LocalDateTime to) {
        return Map.of(
                "gte", from.toInstant(ZoneOffset.UTC).toString(),
                "lte", to.toInstant(ZoneOffset.UTC).toString());
    }

    private List<SiemDtos.ElasticDocument> parseHits(JsonNode root) {
        List<SiemDtos.ElasticDocument> result = new ArrayList<>();
        for (JsonNode hit : root.path("hits").path("hits")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> source = objectMapper.convertValue(hit.path("_source"), Map.class);
            result.add(new SiemDtos.ElasticDocument(hit.path("_id").asText(), hit.path("_index").asText(), source));
        }
        return result;
    }

    JsonNode request(String method, String path, String body, Duration timeout) {
        ensureEnabled();
        try {
            String password = Files.readString(passwordFile, StandardCharsets.UTF_8).trim();
            String credentials = Base64.getEncoder().encodeToString(
                    (username + ":" + password).getBytes(StandardCharsets.UTF_8));
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(timeout)
                    .header("Authorization", "Basic " + credentials)
                    .header("Accept", "application/json");
            if (body == null) {
                builder.method(method, HttpRequest.BodyPublishers.noBody());
            } else {
                builder.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(body));
            }
            HttpResponse<java.io.InputStream> response = client().send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            try(var input=response.body()) {
                if (response.statusCode() < 200 || response.statusCode() >= 300)
                    throw new ServiceUnavailableException("Elasticsearch tra ve ma " + response.statusCode() + ".");
                byte[] bytes=input.readNBytes(16*1024*1024+1);
                if(bytes.length>16*1024*1024)throw new ServiceUnavailableException("ELK_RESPONSE_TOO_LARGE: reduce the page/range; no fields were cropped.");
                return objectMapper.readTree(bytes);
            }
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("Khong the ket noi Elasticsearch: " + exception.getClass().getSimpleName());
        }
    }

    private HttpClient client() throws Exception {
        HttpClient current = httpClient;
        if (current != null) return current;
        synchronized (this) {
            if (httpClient == null) {
                if (!baseUrl.startsWith("https://")) {
                    throw new IllegalStateException("SIEM Elasticsearch URL must use HTTPS");
                }
                String pem = Files.readString(caFile, StandardCharsets.US_ASCII);
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
                KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStore.load(null, null);
                trustStore.setCertificateEntry("siem-ca", certificate);
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
                httpClient = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .connectTimeout(Duration.ofSeconds(4))
                        .build();
            }
            return httpClient;
        }
    }

    private void ensureEnabled() {
        if (!enabled) throw new ServiceUnavailableException("SIEM chua duoc bat tren server.");
    }

    private void validateRange(LocalDateTime from, LocalDateTime to) {
        if (from == null || to == null || to.isBefore(from)) {
            throw new BadRequestException("Khoang thoi gian khong hop le.");
        }
        if (Duration.between(from, to).toDays() > 7) {
            throw new BadRequestException("Khoang thoi gian truy van toi da la 7 ngay.");
        }
    }

    private String firstText(JsonNode source, String... pointers) {
        for (String pointer : pointers) {
            String value = text(source, pointer);
            if (value != null && !value.isBlank()) return value;
        }
        return null;
    }

    private String text(JsonNode source, String pointer) {
        JsonNode value = field(source, pointer);
        if (value.isArray()) return value.isEmpty() ? null : value.path(0).asText(null);
        return value.asText(null);
    }

    private JsonNode field(JsonNode source, String pointer) {
        String dottedName = pointer.startsWith("/")
                ? pointer.substring(1).replace('/', '.')
                : pointer;
        JsonNode flattened = source.get(dottedName);
        return flattened == null ? source.at(pointer) : flattened;
    }

    private List<String> textValues(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) return List.of();
        if (!node.isArray()) return List.of(node.asText());
        List<String> values = new ArrayList<>();
        node.forEach(value -> values.add(value.asText()));
        return List.copyOf(values);
    }

    ElasticAlert parseAlert(JsonNode hit) {
        JsonNode source = hit.path("_source");
        List<String> sourceIps = textValues(field(source, "/source/ip"));
        String serviceId = firstText(source, "/service/id", "/service/name");
        if (serviceId == null || serviceId.isBlank()) {
            serviceId = "flare-web";
        }
        return new ElasticAlert(
                hit.path("_id").asText(),
                hit.path("_index").asText(),
                text(source, "/@timestamp"),
                firstText(source, "/kibana/alert/rule/rule_id", "/rule/id"),
                serviceId,
                sourceIps,
                firstText(source, "/kibana/alert/severity", "/event/severity"),
                firstText(source, "/kibana/alert/rule/name", "/message"));
    }

    public record ElasticAlert(
            String id,
            String index,
            String timestamp,
            String ruleId,
            String serviceId,
            List<String> sourceIps,
            String severity,
            String title
    ) {
    }

    public record AlertPage(List<ElasticAlert> alerts, List<Object> nextSort) {
    }
}
