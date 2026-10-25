package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;

class SiemElasticGatewayTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SiemElasticGateway gateway = new SiemElasticGateway(
            objectMapper,
            false,
            "https://elasticsearch:9200",
            "flare_siem_reader",
            "/not-used/password",
            "/not-used/ca");

    @Test
    void parsesFlattenedElasticSecurityAlertFields() throws Exception {
        var hit = objectMapper.readTree("""
                {
                  "_id": "alert-1",
                  "_index": ".alerts-security.alerts-flare-lab-000001",
                  "_source": {
                    "@timestamp": "2026-09-20T12:06:25.009Z",
                    "kibana.alert.rule.rule_id": "flare-lab-auth-bruteforce",
                    "kibana.alert.rule.name": "Flare Lab: authentication brute-force signal",
                    "kibana.alert.severity": "high",
                    "source.ip": "172.31.0.1"
                  }
                }
                """);

        var alert = gateway.parseAlert(hit);

        assertThat(alert.ruleId()).isEqualTo("flare-lab-auth-bruteforce");
        assertThat(alert.title()).isEqualTo("Flare Lab: authentication brute-force signal");
        assertThat(alert.severity()).isEqualTo("high");
        assertThat(alert.sourceIps()).containsExactly("172.31.0.1");
        assertThat(alert.serviceId()).isEqualTo("flare-web");
    }

    @Test
    void stillParsesNestedEcsFields() throws Exception {
        var hit = objectMapper.readTree("""
                {
                  "_id": "alert-2",
                  "_index": "alerts",
                  "_source": {
                    "@timestamp": "2026-09-20T12:06:25Z",
                    "rule": {"id": "rule-2"},
                    "service": {"id": "checkout"},
                    "source": {"ip": ["203.0.113.10"]},
                    "event": {"severity": "medium"},
                    "message": "Nested alert"
                  }
                }
                """);

        var alert = gateway.parseAlert(hit);

        assertThat(alert.ruleId()).isEqualTo("rule-2");
        assertThat(alert.serviceId()).isEqualTo("checkout");
        assertThat(alert.sourceIps()).containsExactly("203.0.113.10");
        assertThat(alert.title()).isEqualTo("Nested alert");
    }

    @Test
    void accountSecurityQueryRequiresIdentityAndReturnsOnlyAllowlistedGeoFields() throws Exception {
        var query = objectMapper.readTree(gateway.securityQuery("customer-1", "203.0.113.55",
                LocalDateTime.of(2026, 9, 26, 9, 0), LocalDateTime.of(2026, 9, 26, 10, 0), 100));
        assertThat(query.path("query").path("bool").path("minimum_should_match").asInt()).isEqualTo(1);
        assertThat(query.path("query").path("bool").path("should").toString())
                .contains("customer-1", "user.id", "target.user.id");
        assertThat(query.path("query").path("bool").path("filter").toString())
                .contains("203.0.113.55", "@timestamp");
        assertThat(query.path("_source").toString())
                .contains("source.geo.country_name", "flare.source_ip_scope")
                .doesNotContain("cookie", "password", "url.original", "body");
    }
}
