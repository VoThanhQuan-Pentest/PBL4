package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.integration.ContainerizedIntegrationTest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest(properties = "siem.prevention.enabled=false")
@org.springframework.transaction.annotation.Transactional
class SiemIpProviderRoundTripIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper mapper;
    @TempDir Path temporarySecrets;

    @org.junit.jupiter.api.BeforeEach
    void isolateTheManualWorkerQueueWithinTheRolledBackTestTransaction() {
        // Other test contexts use the shared Testcontainers database. Hide
        // their pending fixtures only within this transaction; rollback restores
        // them and also removes this test's requests/cache/attempt records.
        jdbc.update("UPDATE siem_ip_lookup_requests SET status='DONE' WHERE status IN ('PENDING','RUNNING')");
    }

    @Test
    void fixedProviderRequestsPersistFreshEvidenceAndReuseCache() throws Exception {
        Path ipinfoToken = temporarySecrets.resolve("ipinfo.token");
        Path abuseKey = temporarySecrets.resolve("abuseipdb.key");
        Files.writeString(ipinfoToken, "fixture-ipinfo-token", StandardCharsets.UTF_8);
        Files.writeString(abuseKey, "fixture-abuse-key", StandardCharsets.UTF_8);
        AtomicInteger calls = new AtomicInteger();
        var worker = new SiemIpIntelligenceWorker(jdbc, mapper,
                ipinfoToken.toString(), abuseKey.toString(), true, request -> {
                    calls.incrementAndGet();
                    String json;
                    if ("api.ipinfo.io".equals(request.uri().getHost())) {
                        assertThat(request.uri().getPath()).isEqualTo("/lite/11.12.13.14");
                        assertThat(request.uri().getRawQuery()).isEqualTo("token=fixture-ipinfo-token");
                        json = """
                                {"ip":"11.12.13.14","country_code":"US",
                                 "asn":"AS64501","as_name":"Fixture Network"}
                                """;
                    } else {
                        assertThat(request.uri().getHost()).isEqualTo("api.abuseipdb.com");
                        assertThat(request.uri().getPath()).isEqualTo("/api/v2/check");
                        assertThat(request.uri().getRawQuery())
                                .isEqualTo("ipAddress=11.12.13.14&maxAgeInDays=30");
                        assertThat(request.headers().firstValue("Key"))
                                .hasValue("fixture-abuse-key");
                        json = """
                                {"data":{"ipAddress":"11.12.13.14","countryCode":"US",
                                 "abuseConfidenceScore":85,"totalReports":7,"numDistinctUsers":3}}
                                """;
                    }
                    @SuppressWarnings("unchecked")
                    HttpResponse<byte[]> response = mock(HttpResponse.class);
                    when(response.statusCode()).thenReturn(200);
                    when(response.body()).thenReturn(json.getBytes(StandardCharsets.UTF_8));
                    return response;
                });

        queue("11.12.13.14");
        worker.processOne();
        assertThat(calls).hasValue(2);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_intelligence
                WHERE ip_address='11.12.13.14' AND status='FRESH'
                  AND data_provenance='REAL'
                """, Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("""
                SELECT asn FROM siem_ip_intelligence
                WHERE ip_address='11.12.13.14' AND provider='IPINFO'
                """, String.class)).isEqualTo("AS64501");
        assertThat(jdbc.queryForObject("""
                SELECT abuse_score FROM siem_ip_intelligence
                WHERE ip_address='11.12.13.14' AND provider='ABUSEIPDB'
                """, Integer.class)).isEqualTo(85);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_provider_attempts WHERE ip_address='11.12.13.14'
                """, Long.class)).isEqualTo(2);

        queue("11.12.13.14");
        worker.processOne();
        assertThat(calls).hasValue(2);
        queue("192.0.2.19");
        worker.processOne();
        assertThat(calls).hasValue(2);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_provider_attempts
                WHERE ip_address='192.0.2.19'
                """, Long.class)).isZero();
    }

    @Test
    void pastedIpinfoUrlIsMarkedInvalidWithoutAProviderCall() throws Exception {
        Path ipinfoToken = temporarySecrets.resolve("ipinfo.token");
        Path abuseKey = temporarySecrets.resolve("abuseipdb.key");
        Files.writeString(ipinfoToken, "https://api.ipinfo.io/lite/1.1.1.1?token=example",
                StandardCharsets.UTF_8);
        Files.writeString(abuseKey, "", StandardCharsets.UTF_8);
        AtomicInteger calls = new AtomicInteger();
        var worker = new SiemIpIntelligenceWorker(jdbc, mapper,
                ipinfoToken.toString(), abuseKey.toString(), true, request -> {
                    calls.incrementAndGet();
                    throw new AssertionError("Malformed credentials must not reach a provider.");
                });

        assertThat(worker.providerState("IPINFO")).isEqualTo("INVALID_CONFIG");
        queue("11.12.13.15");
        worker.processOne();
        assertThat(calls).hasValue(0);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_intelligence
                WHERE ip_address='11.12.13.15' AND provider='IPINFO'
                  AND status='INVALID_CONFIG' AND data_provenance='UNAVAILABLE'
                """, Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_provider_attempts WHERE ip_address='11.12.13.15'
                """, Long.class)).isZero();
    }

    private void queue(String ip) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                INSERT INTO siem_ip_lookup_requests
                    (id,ip_address,reason,status,requested_at)
                VALUES (?,?,'TEST_FIXTURE','PENDING',?)
                """, "provider-test-" + UUID.randomUUID(), ip, now);
    }
}
