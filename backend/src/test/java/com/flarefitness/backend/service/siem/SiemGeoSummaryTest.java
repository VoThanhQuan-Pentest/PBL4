package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.time.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class SiemGeoSummaryTest {
    @Test void separatesMissingPublicEnrichmentReservedScopesNoLogsAndElasticOutage() throws Exception {
        ObjectMapper mapper=new ObjectMapper();
        SiemElasticGateway gateway=spy(new SiemElasticGateway(mapper,true,"https://elastic:9200","reader","unused","unused"));
        LocalDateTime from=LocalDateTime.of(2026,10,23,0,0),to=from.plusDays(1);
        doReturn(List.of()).when(gateway).geo(from,to);
        doReturn(mapper.readTree("""
            {"hits":{"total":{"value":10}},"aggregations":{"geolocated":{"doc_count":0},
             "public_missing":{"doc_count":3},"scopes":{"buckets":[{"key":"private","doc_count":7}]}}}
            """)).when(gateway).request(eq("POST"),endsWith("/_search"),anyString(),any());
        var missing=gateway.geoSummary(from,to);
        assertThat(missing.sourceStatus()).isEqualTo("AVAILABLE");assertThat(missing.events()).isEqualTo(10);
        assertThat(missing.publicWithoutGeo()).isEqualTo(3);assertThat(missing.scopes()).containsEntry("private",7L);
        doReturn(mapper.readTree("{\"hits\":{\"total\":{\"value\":0}}}")).when(gateway).request(eq("POST"),endsWith("/_search"),anyString(),any());
        assertThat(gateway.geoSummary(from,to).events()).isZero();
        doThrow(new ServiceUnavailableException("Offline")).when(gateway).request(eq("POST"),endsWith("/_search"),anyString(),any());
        assertThat(gateway.geoSummary(from,to).sourceStatus()).isEqualTo("UNAVAILABLE");
        assertThat(new SiemElasticGateway(mapper,false,"https://elastic:9200","reader","unused","unused").geoSummary(from,to).sourceStatus()).isEqualTo("DISABLED");
    }
}
