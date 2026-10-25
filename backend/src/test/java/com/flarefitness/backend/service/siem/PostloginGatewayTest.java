package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PostloginGatewayTest {
    @TempDir Path tmp;
    @Test void pinsIdentityEchoThresholdAndBodyAndPreservesLegacyDisabledState() throws Exception {
        var json=new ObjectMapper();var file=tmp.resolve("token");Files.writeString(file,"a".repeat(32));
        var packet=Map.<String,Object>of("snapshot_id","snapshot-test","as_of","2026-10-22T00:00:00Z",
                "baseline_established",true,"trusted_window_count",30);
        var result=new LinkedHashMap<String,Object>(Map.of("snapshot_id","snapshot-test","as_of",packet.get("as_of"),
                "raw_score",.5,"normal_percentile",99.99,"threshold",99.99,"above_threshold",true,
                "cohort","READY","trusted_window_count",30,"context","BEHAVIOR_REVIEW_CONTEXT"));
        var response=new LinkedHashMap<String,Object>(Map.of("model_version",PostloginDecisionPolicy.MODEL,
                "model_sha256","7bf434569e388ac7c53ad0c19e1eef5b0d65d6848c1970da21638ce9e953a7aa",
                "manifest_sha256","b".repeat(64),"qualification_scope","PROJECT_LIMITED",
                "data_provenance","DEMO_ONLY_RULE_DISTILLATION","feature_schema_version",6,
                "evaluation_unit","SENSITIVE_ACTION_ATTEMPT","runtime_state_sha256","c".repeat(64),
                "calibration_sha256","d".repeat(64),"assessments",List.of(result)));
        var body=new AtomicReference<String>();var received=new AtomicReference<String>();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/postlogin/score",exchange->{
            assertThat(exchange.getRequestHeaders().getFirst("X-UEBA-Token")).isEqualTo("a".repeat(32));
            received.set(new String(exchange.getRequestBody().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
            byte[] bytes=body.get().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,bytes.length);
            try(var output=exchange.getResponseBody()) { output.write(bytes); }
        });server.start();
        try {
            var gateway=new SiemUebaGateway(false,"http://127.0.0.1:"+server.getAddress().getPort(),file.toString(),json);
            body.set(json.writeValueAsString(response));
            assertThat(gateway.scorePostlogin(packet,"b".repeat(64)).aboveThreshold()).isTrue();
            assertThat(json.readTree(received.get()).fieldNames()).toIterable().containsExactly("snapshots");
            for (String field:List.of("snapshot_id","as_of","cohort","context")) {
                Object before=result.put(field,"wrong");body.set(json.writeValueAsString(response));
                assertThatThrownBy(()->gateway.scorePostlogin(packet,"b".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
                result.put(field,before);
            }
            result.put("above_threshold",false);body.set(json.writeValueAsString(response));
            assertThatThrownBy(()->gateway.scorePostlogin(packet,"b".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
            result.put("above_threshold",true);response.put("qualification_scope","SIEM_FINAL");body.set(json.writeValueAsString(response));
            assertThatThrownBy(()->gateway.scorePostlogin(packet,"b".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
            body.set("x".repeat(65537));
            assertThatThrownBy(()->gateway.scorePostlogin(packet,"b".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
        } finally { server.stop(0); }
    }
    @Test void workerDeadlineIsBoundedAndNeverReturnsAnAuthorizingDefault() throws Exception {
        Path token=tmp.resolve("token");Files.writeString(token,"e".repeat(32));
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/postlogin/score",e->{
            try { Thread.sleep(900); } catch(InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            e.close();
        });server.start();
        try {
            var gateway=new SiemUebaGateway(false,"http://127.0.0.1:"+server.getAddress().getPort(),token.toString(),new ObjectMapper());
            long start=System.nanoTime();
            assertThatThrownBy(()->gateway.scorePostlogin(Map.of(),"a".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
            assertThat((System.nanoTime()-start)/1_000_000).isLessThan(800);
        } finally { server.stop(0); }
    }
}
