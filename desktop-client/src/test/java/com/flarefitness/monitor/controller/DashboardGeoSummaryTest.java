package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.flarefitness.monitor.model.SiemModels;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DashboardGeoSummaryTest {
    @Test
    void showsEnrichedCityCountryAndAsnForPublicIp() {
        var document = new SiemModels.ElasticDocument("event-1", "logs-flare.security-lab",
                Map.of("source", Map.of("geo", Map.of("city_name", "London",
                        "country_name", "United Kingdom"), "as", Map.of("number", 12345))));
        assertEquals("GeoIP London, United Kingdom · ASN 12345",
                DashboardController.geoSummary(List.of(document)));
    }

    @Test
    void doesNotInventLocationForReservedIp() {
        var document = new SiemModels.ElasticDocument("event-2", "logs-flare.security-lab",
                Map.of("flare", Map.of("source_ip_scope", "test_net")));
        assertEquals("GeoIP không áp dụng cho IP test_net.",
                DashboardController.geoSummary(List.of(document)));
    }
}
