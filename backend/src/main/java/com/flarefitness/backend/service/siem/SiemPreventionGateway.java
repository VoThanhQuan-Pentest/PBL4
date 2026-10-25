package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.PreventionDtos;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Tests candidate definitions with the same Coraza engine that enforces them. */
@Component
public class SiemPreventionGateway {
    private final ObjectMapper mapper;
    private final URI testUri;
    private final URI healthUri;
    private final Path tokenFile;
    private final boolean enabled;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    public SiemPreventionGateway(ObjectMapper mapper,
            @Value("${siem.prevention.gateway-url:http://gateway:8082}") String gatewayUrl,
            @Value("${siem.prevention.service-token-file:/run/flare-secrets/prevention.token}")
                    String tokenFile,
            @Value("${siem.prevention.enabled:false}") boolean enabled) {
        this.mapper = mapper;
        this.testUri = URI.create(gatewayUrl + "/internal/v1/prevention/test");
        this.healthUri = URI.create(gatewayUrl + "/healthz");
        this.tokenFile = Path.of(tokenFile);
        this.enabled = enabled;
    }

    public GatewayHealth health() {
        if (!enabled) return new GatewayHealth(false, -1, "DISABLED");
        try {
            HttpRequest request = HttpRequest.newBuilder(healthUri)
                    .timeout(Duration.ofSeconds(2)).GET().build();
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200 || response.body().length > 2048) {
                return new GatewayHealth(false, -1, "OFFLINE");
            }
            JsonNode root = mapper.readTree(response.body());
            return new GatewayHealth("UP".equals(root.path("status").asText()),
                    root.path("policy_version").asLong(-1),
                    root.path("redis_state").asText("UNKNOWN"),
                    root.path("policy_schema_version").asInt(1)>=2 && root.path("durable_policy").asBoolean(false));
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            return new GatewayHealth(false, -1, "OFFLINE");
        }
    }

    public record GatewayHealth(boolean available, long version, String redisState, boolean supportsUntilRevoked) {
        public GatewayHealth(boolean available,long version,String redisState) {this(available,version,redisState,false);}
    }

    public PreventionDtos.TestResult test(PreventionDtos.Signature signature,
                                           List<PreventionDtos.TestFixture> fixtures,
                                           String definitionHash) {
        if (!enabled) throw new ServiceUnavailableException("Prevention gateway is disabled.");
        try {
            String token = Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
            if (token.length() < 32 || token.length() > 256) {
                throw new ServiceUnavailableException("Prevention service token is unavailable.");
            }
            Map<String, Object> candidate = new LinkedHashMap<>();
            candidate.put("id", signature.id());
            candidate.put("kind", signature.kind().name());
            candidate.put("http_method", signature.httpMethod());
            candidate.put("path_prefix", signature.pathPrefix());
            candidate.put("match_value", signature.matchValue());
            candidate.put("action", "BLOCK");
            List<Map<String, Object>> samples = new ArrayList<>(fixtures.size());
            for (var item : fixtures) {
                Map<String, Object> sample = new LinkedHashMap<>();
                sample.put("http_method", item.httpMethod());
                sample.put("request_path", item.requestPath());
                sample.put("request_body", item.requestBody());
                sample.put("expected_match", item.expectedMatch());
                samples.add(sample);
            }
            byte[] body = mapper.writeValueAsBytes(Map.of("signature", candidate, "fixtures", samples));
            HttpRequest request = HttpRequest.newBuilder(testUri)
                    .timeout(Duration.ofSeconds(4))
                    .header("X-Flare-Service-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200 || response.body().length > 2048) {
                throw new ServiceUnavailableException(
                        "Gateway fixture test unavailable (HTTP " + response.statusCode() + ").");
            }
            JsonNode answer = mapper.readTree(response.body());
            if (!answer.path("passed").isBoolean()
                    || !answer.path("passed_cases").isInt()
                    || !answer.path("total_cases").isInt()
                    || answer.path("total_cases").asInt() != fixtures.size()) {
                throw new ServiceUnavailableException("Gateway returned an invalid fixture result.");
            }
            return new PreventionDtos.TestResult(answer.path("passed").asBoolean(),
                    answer.path("passed_cases").asInt(), answer.path("total_cases").asInt(),
                    definitionHash);
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new ServiceUnavailableException("Gateway fixture test unavailable.");
        }
    }
}
