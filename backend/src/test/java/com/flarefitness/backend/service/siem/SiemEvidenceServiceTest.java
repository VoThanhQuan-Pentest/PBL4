package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.flarefitness.backend.exception.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;

class SiemEvidenceServiceTest {
    ObjectMapper mapper=new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .setNodeFactory(JsonNodeFactory.withExactBigDecimals(true));
    SiemElasticGateway elastic=mock(SiemElasticGateway.class);
    SiemEvidenceService service=new SiemEvidenceService(elastic,mapper);
    SiemEvidenceService.Filter filter=new SiemEvidenceService.Filter(LocalDateTime.of(2026,10,23,0,0),LocalDateTime.of(2026,10,24,0,0),null,null,null,null,1);
    @BeforeEach void setup() throws Exception {
        when(elastic.isEnabled()).thenReturn(true);
        when(elastic.request(eq("POST"),contains("/_pit?"),isNull(),any())).thenReturn(mapper.readTree("{\"id\":\"pit-1\"}"));
    }
    @Test void returnsNativeHitWithNoCropOrApplicationMetadataAndExactNumbers() throws Exception {
        JsonNode hit=mapper.readTree("""
            {"_index":".ds-logs-flare.security-lab-2026.10.23-000001","_id":"abc","_score":null,
             "_source":{"@timestamp":"2026-10-23T12:00:00Z","dotted.key":"Tiếng Việt 👩‍💻",
              "huge":123456789012345678901234567890,"decimal":0.123456789012345678901234567890,
              "nested":{"array":[null,true,1,"x",{"name":"y"}]},"empty":[]},
             "fields":{"event.dataset":["flare.security"]},"sort":[1,12]}
            """);
        when(elastic.request(eq("POST"),eq("/_search"),anyString(),any())).thenReturn(mapper.createObjectNode().set("hits",mapper.createObjectNode().set("hits",mapper.createArrayNode().add(hit))));
        var result=service.search(filter,null,"incident-1",Set.of());
        assertThat(result.content().getFirst().elkHit()).isEqualTo(hit);
        assertThat(result.content().getFirst().elkHit().path("_source").get("huge").bigIntegerValue().toString()).isEqualTo("123456789012345678901234567890");
        assertThat(result.content().getFirst().elkHit().path("_source").get("decimal").decimalValue().toPlainString()).isEqualTo("0.123456789012345678901234567890");
        assertThat(result.content().getFirst().association().matchType()).isEqualTo("RELATED");
        assertThat(hit.path("_source").has("association")).isFalse();
        verify(elastic).request(eq("POST"),eq("/_search"),argThat(body->!body.contains("\"_source\"")),any());
        assertThatThrownBy(()->service.search(new SiemEvidenceService.Filter(filter.from(),filter.to(),"flare.security",null,null,null,1),result.nextCursor(),"incident-1",Set.of())).isInstanceOf(BadRequestException.class);
    }
    @Test void refusesSensitiveSourceRatherThanRedactingIt() throws Exception {
        for(String key:List.of("password","http.request.body.content","authorization","cookie","access_token")) {
            var hit=mapper.createObjectNode().put("_index","logs-flare.security-lab").put("_id","x");
            hit.putObject("_source").putObject("nested").put(key,"private");
            assertThatThrownBy(()->SiemEvidenceService.requireSafeHit(hit)).isInstanceOf(BadRequestException.class).hasMessageContaining("RAW_VIEW_REFUSED");
        }
    }
    @Test void restrictsIndicesPageSizeAndDistinguishesUnavailableFromNoHits() {
        assertThat(SiemEvidenceService.allowedIndex(".security-7")).isFalse();
        assertThat(SiemEvidenceService.allowedIndex("logs-flare.security-lab/_search")).isFalse();
        assertThatThrownBy(()->service.search(new SiemEvidenceService.Filter(filter.from(),filter.to(),".security",null,null,null,1000),null,null,Set.of())).isInstanceOf(BadRequestException.class);
        when(elastic.request(eq("POST"),contains("/_pit?"),isNull(),any())).thenThrow(new ServiceUnavailableException("Offline"));
        assertThat(service.search(filter,null,null,Set.of()).sourceStatus()).isEqualTo("UNAVAILABLE");
    }
    @AfterEach void clearSecurity(){org.springframework.security.core.context.SecurityContextHolder.clearContext();}
    @Test void directEventQueryDoesNotRequireTheOldSourceOrTarget()throws Exception {
        var scoped=new SiemEvidenceService.Filter(filter.from(),filter.to(),null,null,"192.0.2.25","old-account",10);
        String body=mapper.writeValueAsString(SiemEvidenceService.query(scoped,Set.of(),Set.of("real-attempt"),false));
        assertThat(body).contains("real-attempt","event.id").doesNotContain("192.0.2.25","old-account");
        String related=mapper.writeValueAsString(SiemEvidenceService.query(scoped,Set.of(),Set.of("real-attempt"),true));
        assertThat(related).contains("real-attempt","192.0.2.25","old-account");
    }
    @Test void cursorCannotBeReusedByAnotherPrincipal()throws Exception {
        JsonNode hit=mapper.readTree("{\"_index\":\"logs-flare.security-lab\",\"_id\":\"x\",\"_source\":{},\"sort\":[1,2]}");
        when(elastic.request(eq("POST"),eq("/_search"),anyString(),any())).thenReturn(mapper.createObjectNode().set("hits",mapper.createObjectNode().set("hits",mapper.createArrayNode().add(hit))));
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("l1",null));
        var first=service.search(filter,null,"case",Set.of());assertThat(first.nextCursor()).isNotNull();
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("l2",null));
        assertThatThrownBy(()->service.search(filter,first.nextCursor(),"case",Set.of())).isInstanceOf(BadRequestException.class);
    }

    @Test void summaryAndQueueComputeTheEarliestDirectLogWithoutLoadingOrPagingHits()throws Exception {
        var first=mapper.readTree("{\"value\":1792756800000,\"value_as_string\":\"2026-10-23T12:00:00.000Z\"}");
        var response=mapper.createObjectNode();response.putObject("_shards").put("failed",0);
        var aggs=response.putObject("aggregations");aggs.set("first_observed_at",first);
        aggs.putObject("incidents").putObject("buckets").putObject("case").set("first_observed_at",first);
        when(elastic.request(eq("POST"),endsWith("/_search"),anyString(),any())).thenReturn(response);
        var at=LocalDateTime.of(2026,10,23,12,0);
        assertThat(service.aggregate(filter,Set.of(),Set.of("original-event")).firstObservedAt()).isEqualTo(at);
        var scope=new SiemWorkspaceService.EvidenceScope(null,filter,Set.of(),Set.of("original-event"),false);
        assertThat(service.aggregateBatch(Map.of("case",scope)).get("case").firstObservedAt()).isEqualTo(at);
        verify(elastic,times(2)).request(eq("POST"),endsWith("/_search"),argThat(body->{
            try {var node=mapper.readTree(body);return node.path("size").asInt()==0 && body.contains("first_observed_at") && body.contains("original-event") && body.contains("strict_date_time");}
            catch(Exception error){return false;}
        }),any());
    }

    @Test void partialOrEmptyEvidenceCannotEstablishTheFirstLogTime()throws Exception {
        for(String payload:List.of(
                "{\"timed_out\":true,\"aggregations\":{\"first_observed_at\":{\"value\":1,\"value_as_string\":\"2026-10-23T12:00:00Z\"}}}",
                "{\"_shards\":{\"failed\":1},\"aggregations\":{\"first_observed_at\":{\"value\":1,\"value_as_string\":\"2026-10-23T12:00:00Z\"}}}",
                "{\"aggregations\":{\"first_observed_at\":{\"value\":null}}}")) {
            when(elastic.request(eq("POST"),endsWith("/_search"),anyString(),any())).thenReturn(mapper.readTree(payload));
            assertThat(service.aggregate(filter,Set.of(),Set.of("event")).firstObservedAt()).isNull();
        }
    }

}
