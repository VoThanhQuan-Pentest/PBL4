package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodySubscriber;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Background-only provider lookup. Never used in the incoming request path. */
@Component
public class SiemIpIntelligenceWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SiemIpIntelligenceWorker.class);
    private static final int DAILY_BUDGET = 100;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final Path ipinfoTokenFile;
    private final Path abuseIpDbKeyFile;
    private final boolean enabled;
    private final ProviderTransport transport;

    @Autowired
    public SiemIpIntelligenceWorker(JdbcTemplate jdbc, ObjectMapper mapper,
            @Value("${siem.prevention.ipinfo-token-file:/run/flare-secrets/ipinfo.token}") String ipinfoTokenFile,
            @Value("${siem.prevention.abuseipdb-key-file:/run/flare-secrets/abuseipdb.key}") String abuseIpDbKeyFile,
            @Value("${siem.prevention.enabled:false}") boolean enabled) {
        this(jdbc, mapper, ipinfoTokenFile, abuseIpDbKeyFile, enabled,
                liveTransport());
    }

    SiemIpIntelligenceWorker(JdbcTemplate jdbc, ObjectMapper mapper,
            String ipinfoTokenFile, String abuseIpDbKeyFile,
            boolean enabled, ProviderTransport transport) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.ipinfoTokenFile = Path.of(ipinfoTokenFile);
        this.abuseIpDbKeyFile = Path.of(abuseIpDbKeyFile);
        this.enabled = enabled;
        this.transport = transport;
    }

    @FunctionalInterface
    interface ProviderTransport {
        HttpResponse<byte[]> send(HttpRequest request) throws IOException, InterruptedException;
    }

    private static ProviderTransport liveTransport() {
        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        return request -> http.send(request, ignored -> new LimitedBodySubscriber(32768));
    }

    public String providerState(String provider) {
        if (!enabled) return "DISABLED";
        Path file = "IPINFO".equals(provider) ? ipinfoTokenFile : abuseIpDbKeyFile;
        try {
            if (!Files.isRegularFile(file)) return "NOT_CONFIGURED";
            if (Files.size(file) > 256) return "INVALID_CONFIG";
            String key = Files.readString(file, StandardCharsets.UTF_8).trim();
            if (key.isBlank()) return "NOT_CONFIGURED";
            return invalidCredential(key) ? "INVALID_CONFIG" : "CONFIGURED";
        } catch (IOException exception) {
            return "NOT_CONFIGURED";
        }
    }

    @Scheduled(fixedDelayString = "${siem.prevention.lookup-interval-ms:5000}")
    public void processOne() {
        if (!enabled) return;
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                UPDATE siem_ip_lookup_requests SET status='PENDING'
                WHERE status='RUNNING' AND requested_at<?
                """, now.minusMinutes(5));
        List<Lookup> queue = jdbc.query("""
                SELECT id,ip_address FROM siem_ip_lookup_requests
                WHERE status='PENDING' ORDER BY requested_at LIMIT 1
                """, (row, ignored) -> new Lookup(row.getString(1), row.getString(2)));
        if (queue.isEmpty()) return;
        Lookup lookup = queue.getFirst();
        if (jdbc.update("""
                UPDATE siem_ip_lookup_requests SET status='RUNNING'
                WHERE id=? AND status='PENDING'
                """, lookup.id()) != 1) return;
        try {
            String ip = SiemPreventionService.canonicalPublicIp(lookup.ip());
            lookupProvider(ip, "IPINFO", ipinfoTokenFile, Duration.ofHours(24));
            lookupProvider(ip, "ABUSEIPDB", abuseIpDbKeyFile, Duration.ofHours(6));
            jdbc.update("""
                    UPDATE siem_ip_lookup_requests SET status='DONE',completed_at=? WHERE id=?
                    """, LocalDateTime.now(ZoneOffset.UTC), lookup.id());
        } catch (RuntimeException exception) {
            jdbc.update("""
                    UPDATE siem_ip_lookup_requests SET status='ERROR',completed_at=? WHERE id=?
                    """, LocalDateTime.now(ZoneOffset.UTC), lookup.id());
            LOGGER.warn("IP intelligence job failed jobId={} exceptionType={}",
                    lookup.id(), exception.getClass().getSimpleName());
        }
    }

    private void lookupProvider(String ip, String provider, Path keyFile, Duration ttl) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        Long fresh = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_intelligence
                WHERE ip_address=? AND provider=? AND expires_at>?
                """, Long.class, ip, provider, now);
        if (fresh != null && fresh > 0) return;
        String key;
        try {
            if (Files.size(keyFile) > 256) {
                save(ip, provider, "INVALID_CONFIG", new ProviderResult(), now.plusMinutes(5));
                return;
            }
            key = Files.readString(keyFile, StandardCharsets.UTF_8).trim();
        } catch (IOException exception) {
            key = "";
        }
        if (key.isBlank()) {
            save(ip, provider, "NOT_CONFIGURED", new ProviderResult(), now.plusMinutes(5));
            return;
        }
        if (invalidCredential(key)) {
            save(ip, provider, "INVALID_CONFIG", new ProviderResult(), now.plusMinutes(5));
            return;
        }
        LocalDateTime today = now.toLocalDate().atStartOfDay();
        Long attempts = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_provider_attempts
                WHERE provider=? AND attempted_at>=?
                """, Long.class, provider, today);
        if (attempts != null && attempts >= DAILY_BUDGET) {
            save(ip, provider, "RATE_LIMITED", new ProviderResult(), now.plusHours(1));
            return;
        }
        String attemptId = "provider-attempt-" + UUID.randomUUID();
        jdbc.update("""
                INSERT INTO siem_ip_provider_attempts
                    (id,provider,ip_address,status,attempted_at)
                VALUES (?,?,?,'STARTED',?)
                """, attemptId, provider, ip, now);
        String status;
        ProviderResult value = new ProviderResult();
        try {
            HttpRequest request = requestFor(provider, ip, key);
            HttpResponse<byte[]> response = transport.send(request);
            if (response.statusCode() == 429) {
                status = "RATE_LIMITED";
            } else if (response.statusCode() == 200) {
                JsonNode json = mapper.readTree(response.body());
                value = "IPINFO".equals(provider) ? parseIpinfo(json, ip) : parseAbuse(json, ip);
                status = "FRESH";
            } else {
                status = "ERROR";
            }
        } catch (IOException | InterruptedException | IllegalArgumentException exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            status = "ERROR";
            LOGGER.warn("Provider lookup failed provider={} exceptionType={}",
                    provider, exception.getClass().getSimpleName());
        }
        jdbc.update("UPDATE siem_ip_provider_attempts SET status=? WHERE id=?", status, attemptId);
        save(ip, provider, status, value, now.plus(
                "FRESH".equals(status) ? ttl : Duration.ofMinutes(5)));
    }

    private HttpRequest requestFor(String provider, String ip, String key) {
        String target = "IPINFO".equals(provider)
                ? "https://api.ipinfo.io/lite/" + ip + "?token=" +
                    URLEncoder.encode(key, StandardCharsets.UTF_8)
                : "https://api.abuseipdb.com/api/v2/check?ipAddress=" +
                    URLEncoder.encode(ip, StandardCharsets.UTF_8) + "&maxAgeInDays=30";
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(target))
                .timeout(Duration.ofSeconds(2))
                .header("Accept", "application/json");
        if ("ABUSEIPDB".equals(provider)) builder.header("Key", key);
        return builder.GET().build();
    }

    static boolean invalidCredential(String value) {
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        return value.length() > 256 || value.chars().anyMatch(
                character -> Character.isWhitespace(character) || Character.isISOControl(character))
                || lower.startsWith("http://") || lower.startsWith("https://")
                || lower.startsWith("bearer ") || lower.startsWith("token=")
                || lower.startsWith("ipinfo_token=") || lower.startsWith("abuseipdb_key=");
    }

    static ProviderResult parseIpinfo(JsonNode root, String ip) {
        if (root == null || !samePublicIp(ip, root.path("ip").asText())) {
            throw new IllegalArgumentException("IPinfo returned a different IP.");
        }
        ProviderResult value = new ProviderResult();
        value.countryCode = optionalText(root, "country_code", 8);
        value.asn = optionalText(root, "asn", 32);
        value.asName = optionalText(root, "as_name", 160);
        // Lite does not contain privacy/abuse data: null means unavailable, not false.
        return value;
    }

    static ProviderResult parseAbuse(JsonNode root, String ip) {
        JsonNode data = root == null ? null : root.path("data");
        if (data == null || !samePublicIp(ip, data.path("ipAddress").asText())) {
            throw new IllegalArgumentException("AbuseIPDB returned a different IP.");
        }
        ProviderResult value = new ProviderResult();
        value.countryCode = optionalText(data, "countryCode", 8);
        value.abuseScore = boundedInt(data, "abuseConfidenceScore", 100);
        value.totalReports = boundedInt(data, "totalReports", Integer.MAX_VALUE);
        value.distinctReporters = boundedInt(data, "numDistinctUsers", Integer.MAX_VALUE);
        return value;
    }

    private static boolean samePublicIp(String expected, String actual) {
        try {
            return SiemPreventionService.canonicalPublicIp(actual).equals(
                    SiemPreventionService.canonicalPublicIp(expected));
        } catch (RuntimeException invalid) {
            return false;
        }
    }

    private static String optionalText(JsonNode node, String field, int max) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        if (!value.isTextual() || value.asText().length() > max) {
            throw new IllegalArgumentException("Invalid provider field.");
        }
        return value.asText();
    }

    private static Integer boundedInt(JsonNode node, String field, int max) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        if (!value.isInt() || value.intValue() < 0 || value.intValue() > max) {
            throw new IllegalArgumentException("Invalid provider number.");
        }
        return value.intValue();
    }

    private void save(String ip, String provider, String status, ProviderResult data,
                      LocalDateTime expires) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                INSERT INTO siem_ip_intelligence
                    (id,ip_address,provider,status,country_code,asn,as_name,
                     anonymous_flag,hosting_flag,abuse_score,total_reports,
                     distinct_reporters,observed_at,expires_at,data_provenance)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE
                    status=VALUES(status),country_code=VALUES(country_code),
                    asn=VALUES(asn),as_name=VALUES(as_name),
                    anonymous_flag=VALUES(anonymous_flag),hosting_flag=VALUES(hosting_flag),
                    abuse_score=VALUES(abuse_score),total_reports=VALUES(total_reports),
                    distinct_reporters=VALUES(distinct_reporters),
                    observed_at=VALUES(observed_at),expires_at=VALUES(expires_at),
                    data_provenance=VALUES(data_provenance)
                """, "ip-intel-" + UUID.randomUUID(), ip, provider, status,
                data.countryCode, data.asn, data.asName, data.anonymousFlag,
                data.hostingFlag, data.abuseScore, data.totalReports,
                data.distinctReporters, now, expires,
                "FRESH".equals(status) ? "REAL" : "UNAVAILABLE");
    }

    private record Lookup(String id, String ip) { }

    /** Bounds provider response memory and keeps the request timeout effective through body completion. */
    private static final class LimitedBodySubscriber implements BodySubscriber<byte[]> {
        private final int maximum;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private boolean overflow;

        private LimitedBodySubscriber(int maximum) { this.maximum = maximum; }

        @Override
        public CompletionStage<byte[]> getBody() { return result; }

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            value.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (output.size() + buffer.remaining() > maximum) {
                    overflow = true;
                    subscription.cancel();
                    result.completeExceptionally(new IOException("Provider response exceeds limit."));
                    return;
                }
                while (buffer.hasRemaining()) output.write(buffer.get());
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable failure) { result.completeExceptionally(failure); }

        @Override
        public void onComplete() {
            if (!overflow) result.complete(output.toByteArray());
        }
    }

    static final class ProviderResult {
        String countryCode;
        String asn;
        String asName;
        Boolean anonymousFlag;
        Boolean hostingFlag;
        Integer abuseScore;
        Integer totalReports;
        Integer distinctReporters;
    }
}
