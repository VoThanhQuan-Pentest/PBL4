package com.flarefitness.monitor.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SiemApiClientTest {
    @Test void challengeDoesNotEstablishAClientSessionBeforeOtp() throws Exception {
        server.removeContext("/api/auth/login");
        server.createContext("/api/auth/login", exchange -> {
            assertEquals("/api/auth/login", exchange.getRequestURI().getPath());
            respond(exchange, 202, """
                    {"challenge_id":"12345678-1234-1234-1234-123456789012","expires_in":300,
                    "email_masked":"a***@example.test","channel":"EMAIL_OTP"}
                    """, null);
        });
        server.createContext("/api/auth/login/otp", exchange -> {
            assertEquals("csrf-test", exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            var body = new com.fasterxml.jackson.databind.ObjectMapper().readTree(exchange.getRequestBody());
            assertEquals("12345678-1234-1234-1234-123456789012", body.path("challenge_id").asText());
            assertEquals("123456", body.path("otp_code").asText());
            csrfValue.set("csrf-rotated");
            respond(exchange, 200, """
                    {"access_token":null,"expires_in":3600,"user":{"id":"analyst-1",
                    "username":"analyst","role":"Security analyst","ho_ten":"SOC Analyst"}}
                    """, "access_token=jwt-test; Path=/; HttpOnly; SameSite=Strict");
        });
        var client = new SiemApiClient(baseUrl);
        var attempt = client.beginLogin("analyst", "secret").get(3, TimeUnit.SECONDS);
        assertEquals(null, attempt.session());
        assertEquals(300, attempt.challenge().expiresIn());
        var response = client.verifyLoginOtp(attempt.challenge().challengeId(), "123456").get(3, TimeUnit.SECONDS);
        assertEquals("analyst", response.user().username());
        assertEquals(2, client.overview().get(3, TimeUnit.SECONDS).openIncidents());
    }

    @Test void passiveRequestsStopRenewingIdleUntilAnotherUserInteraction() throws Exception {
        var clock = new java.util.concurrent.atomic.AtomicLong(0L);
        var marker = new AtomicReference<String>();
        server.createContext("/api/siem/status", exchange -> {
            marker.set(exchange.getRequestHeaders().getFirst("X-User-Activity"));
            respond(exchange, 200, "{\"elasticsearch_available\":true}", null);
        });
        var client = new SiemApiClient(baseUrl, clock::get);
        client.login("analyst", "secret").get(3, TimeUnit.SECONDS);
        client.status().get(3, TimeUnit.SECONDS);
        assertEquals("1", marker.get());
        clock.set(TimeUnit.SECONDS.toNanos(31));
        client.status().get(3, TimeUnit.SECONDS);
        assertEquals(null, marker.get());
        client.recordUserActivity();
        client.status().get(3, TimeUnit.SECONDS);
        assertEquals("1", marker.get());
        client.clearSession();
        client.status().get(3, TimeUnit.SECONDS);
        assertEquals(null, marker.get());
    }

    @Test
    void readsLimitedPolicyAndSubmitsVersionedReviewsWithAuthenticatedCsrf() throws Exception {
        server.createContext("/api/siem/postlogin-policy",exchange -> respond(exchange,200,
                "{\"mode\":\"OBSERVE\",\"scope\":\"PROJECT_LIMITED\",\"otp_required\":true,\"maximum_hold_seconds\":600}",null));
        server.createContext("/api/siem/postlogin-decisions/pld-test/review",exchange -> {
            assertEquals("csrf-rotated",exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            var body=new com.fasterxml.jackson.databind.ObjectMapper().readTree(exchange.getRequestBody());
            assertEquals(7,body.path("expected_version").asInt());
            assertEquals("UNDETERMINED",body.path("verdict").asText());
            assertEquals("Needs further evidence.",body.path("reason").asText());
            respond(exchange,200,"{\"summary\":{\"id\":\"pld-test\",\"version\":8},\"hold_active\":false,\"reviews\":[]}",null);
        });
        var client=new SiemApiClient(baseUrl);client.login("analyst","secret").get(3,TimeUnit.SECONDS);
        assertTrue(client.postloginPolicy().get(3,TimeUnit.SECONDS).otpRequired());
        var detail=client.reviewPostloginDecision("pld-test",7,"UNDETERMINED","Needs further evidence.").get(3,TimeUnit.SECONDS);
        assertEquals(8,detail.summary().version());
    }
    @Test void newEvidenceApiPreservesNativeJsonAndExactDecimalValues() throws Exception {
        server.createContext("/api/siem/evidence",exchange->respond(exchange,200,"""
            {"content":[{"elk_hit":{"_index":"logs-flare.security-lab","_id":"event-1","_score":null,
              "_source":{"user.name":"Tiếng Việt","large":123456789012345678901234567890,
              "decimal":0.123456789012345678901234567890,"nested":{"items":[true,null,{"value":"x"}]}}
              ,"sort":[1,2]},"association":null}],"next_cursor":"cursor-bound-to-filter","source_status":"AVAILABLE"}
            """,null));
        var client=new SiemApiClient(baseUrl);
        var page=client.evidence(LocalDateTime.of(2026,10,23,0,0),LocalDateTime.of(2026,10,24,0,0),null,null,null,null,null).get(3,TimeUnit.SECONDS);
        var hit=page.content().getFirst().elkHit();
        assertTrue(hit.get("_score").isNull());assertTrue(hit.path("_source").path("nested").path("items").get(1).isNull());
        assertEquals("0.123456789012345678901234567890",hit.path("_source").path("decimal").decimalValue().toPlainString());
        assertEquals("123456789012345678901234567890",hit.path("_source").path("large").bigIntegerValue().toString());
        assertEquals("Tiếng Việt",hit.path("_source").path("user.name").asText());
        assertEquals("cursor-bound-to-filter",page.nextCursor());
    }
    @Test void configuredOriginPrefersSystemPropertyAndRemoteHttpIsRejected() {
        String prior=System.getProperty("flare.soc.serverOrigin");
        try{System.setProperty("flare.soc.serverOrigin",baseUrl);assertEquals(baseUrl,SiemApiClient.configuredOrigin());}
        finally{if(prior==null)System.clearProperty("flare.soc.serverOrigin");else System.setProperty("flare.soc.serverOrigin",prior);}
        assertThrows(IllegalArgumentException.class,()->new SiemApiClient("http://example.org"));
        assertThrows(IllegalArgumentException.class,()->new SiemApiClient("https://user:secret@example.org"));
    }
    private HttpServer server;
    private String baseUrl;
    private final AtomicReference<String> csrfValue = new AtomicReference<>("csrf-test");

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        csrfValue.set("csrf-test");
        server.createContext("/api/auth/csrf", exchange -> respond(exchange, 200,
                "{\"token\":\"" + csrfValue.get() + "\"}",
                "XSRF-TOKEN=" + csrfValue.get() + "; Path=/; SameSite=Strict"));
        server.createContext("/api/auth/login", exchange -> {
            assertEquals("csrf-test", exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            csrfValue.set("csrf-rotated");
            respond(exchange, 200, """
                    {"access_token":null,"expires_in":3600,"user":{"id":"analyst-1",
                    "username":"analyst","role":"Security analyst","ho_ten":"SOC Analyst"}}
                    """, "access_token=jwt-test; Path=/; HttpOnly; SameSite=Strict");
        });
        server.createContext("/api/siem/overview", exchange -> {
            assertTrue(exchange.getRequestHeaders().getFirst("Cookie").contains("access_token=jwt-test"));
            respond(exchange, 200, """
                    {"open_incidents":2,"new_incidents":1,"in_progress_incidents":1,
                    "incidents_last24_hours":3,"by_severity":{},"by_classification":{},
                    "elasticsearch_available":true}
                    """, null);
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void keepsCsrfAndAuthenticationCookiesInTheInMemorySession() throws Exception {
        SiemApiClient client = new SiemApiClient(baseUrl);

        var login = client.login("analyst", "secret").get(3, TimeUnit.SECONDS);
        var overview = client.overview().get(3, TimeUnit.SECONDS);

        assertEquals("Security analyst", login.user().role());
        assertEquals(2, overview.openIncidents());
        assertTrue(overview.elasticsearchAvailable());
    }

    @Test
    void shadowStartSendsOnlyModelIdAndPagesAreBounded() throws Exception {
        var body = new AtomicReference<String>(); var query = new AtomicReference<String>();
        server.createContext("/api/siem/ueba/shadow-runs", exchange -> {
            if (exchange.getRequestMethod().equals("POST")) {
                body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                respond(exchange, 202, """
                        {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","model_version":"owned-shadow-model","status":"STARTING",
                        "data_provenance":"DEMO_ONLY","acknowledged_windows":0,"state":{}}
                        """, null);
            } else {
                query.set(exchange.getRequestURI().getQuery());
                respond(exchange, 200, "{\"content\":[],\"page\":2,\"size\":20,\"total_elements\":0,\"total_pages\":0,\"has_next\":false}", null);
            }
        });
        SiemApiClient client = new SiemApiClient(baseUrl);
        var result = client.startUebaShadow("owned-shadow-model").get(3, TimeUnit.SECONDS);
        assertEquals("STARTING", result.status()); assertEquals(0, result.elapsedSeconds());
        var request = new com.fasterxml.jackson.databind.ObjectMapper().readTree(body.get());
        assertEquals(1, request.size()); assertEquals("owned-shadow-model", request.path("model_version").asText());
        client.uebaShadowRuns(2, 20).get(3, TimeUnit.SECONDS); assertEquals("page=2&size=20", query.get());
        assertThrows(IllegalArgumentException.class, () -> client.uebaShadowRuns(-1, 20));
        assertThrows(IllegalArgumentException.class, () -> client.uebaTrainingJobs(0, 51));
    }

    @Test
    void rejectsCleartextRemoteOrigins() {
        assertThrows(IllegalArgumentException.class, () -> new SiemApiClient("http://198.51.100.10:8080"));
    }

    @Test
    void refreshesCsrfBeforeEveryAdminMutation() throws Exception {
        server.createContext("/api/siem/ueba/training-jobs", exchange -> {
            assertEquals("csrf-rotated", exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            csrfValue.set("csrf-after-training");
            respond(exchange, 202, """
                    {"id":"job-1","model_version":"model-test-1","status":"QUEUED",
                    "data_provenance":"DEMO_ONLY","training_windows":500,"calibration_windows":100}
                    """, null);
        });
        server.createContext("/api/siem/ueba/models/model-test-1/activate", exchange -> {
            assertEquals("csrf-after-training", exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            respond(exchange, 200, """
                    {"id":"job-1","model_version":"model-test-1","status":"ACTIVE",
                    "data_provenance":"DEMO_ONLY","training_windows":500,"calibration_windows":100}
                    """, null);
        });
        SiemApiClient client = new SiemApiClient(baseUrl);
        client.login("analyst", "secret").get(3, TimeUnit.SECONDS);
        var job = client.startUebaTraining(LocalDateTime.of(2026, 9, 1, 0, 0),
                LocalDateTime.of(2026, 9, 10, 0, 0)).get(3, TimeUnit.SECONDS);
        assertEquals("QUEUED", job.status());
        assertEquals("ACTIVE", client.activateUebaModel("model-test-1")
                .get(3, TimeUnit.SECONDS).status());
    }

    @Test
    void logoutRevokesServerSessionAndClearsLocalCookies() throws Exception {
        server.createContext("/api/auth/logout", exchange -> {
            assertEquals("csrf-rotated", exchange.getRequestHeaders().getFirst("X-XSRF-TOKEN"));
            assertTrue(exchange.getRequestHeaders().getFirst("Cookie").contains("access_token=jwt-test"));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        AtomicReference<String> cookieAfterLogout = new AtomicReference<>();
        server.createContext("/api/siem/status", exchange -> {
            cookieAfterLogout.set(exchange.getRequestHeaders().getFirst("Cookie"));
            respond(exchange, 200, "{\"enabled\":true}", null);
        });
        SiemApiClient client = new SiemApiClient(baseUrl);
        client.login("analyst", "secret").get(3, TimeUnit.SECONDS);
        client.logout().get(3, TimeUnit.SECONDS);
        client.status().get(3, TimeUnit.SECONDS);
        assertTrue(cookieAfterLogout.get() == null
                || !cookieAfterLogout.get().contains("access_token=jwt-test"));
    }

    @Test
    void failedServerLogoutStillDiscardsLocalCookies() throws Exception {
        server.createContext("/api/auth/logout", exchange -> respond(exchange, 503,
                "{\"message\":\"Unavailable\"}", null));
        AtomicReference<String> cookieAfterLogout = new AtomicReference<>();
        server.createContext("/api/siem/status", exchange -> {
            cookieAfterLogout.set(exchange.getRequestHeaders().getFirst("Cookie"));
            respond(exchange, 200, "{\"enabled\":true}", null);
        });
        SiemApiClient client = new SiemApiClient(baseUrl);
        client.login("analyst", "secret").get(3, TimeUnit.SECONDS);
        assertThrows(ExecutionException.class, () -> client.logout().get(3, TimeUnit.SECONDS));
        client.status().get(3, TimeUnit.SECONDS);
        assertTrue(cookieAfterLogout.get() == null
                || !cookieAfterLogout.get().contains("access_token=jwt-test"));
    }

    @Test
    void sendsDashboardRangeAndServerSidePriorityFilters() throws Exception {
        AtomicReference<String> summaryQuery = new AtomicReference<>();
        AtomicReference<String> incidentQuery = new AtomicReference<>();
        server.createContext("/api/siem/dashboard-summary", exchange -> {
            summaryQuery.set(exchange.getRequestURI().getRawQuery());
            respond(exchange, 200, """
                    {"from":"2035-01-02T11:00:00","to":"2035-01-02T12:00:00",
                    "total_incidents":4,"investigate_incidents":3,"potential_noise_incidents":1,
                    "closed_incidents":1,"by_severity":{"URGENT":1},"by_status":{"NEW":2},
                    "by_classification":{"INVESTIGATE":3}}
                    """, null);
        });
        server.createContext("/api/siem/incidents", exchange -> {
            incidentQuery.set(exchange.getRequestURI().getRawQuery());
            respond(exchange, 200, """
                    {"content":[],"page":0,"size":10,"total_elements":0,"total_pages":0,"has_next":false}
                    """, null);
        });
        SiemApiClient client = new SiemApiClient(baseUrl);
        LocalDateTime to = LocalDateTime.of(2035, 1, 2, 12, 0);

        var summary = client.dashboardSummary(to.minusHours(1), to).get(3, TimeUnit.SECONDS);
        client.incidents(new com.flarefitness.monitor.model.SiemModels.IncidentQuery(
                0, 10, null, null, "URGENT", "INVESTIGATE",
                "OPEN", "PRIORITY", null, null)).get(3, TimeUnit.SECONDS);

        assertEquals(4, summary.totalIncidents());
        assertTrue(summaryQuery.get().contains("from=2035-01-02T11%3A00"));
        assertTrue(incidentQuery.get().contains("scope=OPEN"));
        assertTrue(incidentQuery.get().contains("sort=PRIORITY"));
        assertTrue(incidentQuery.get().contains("severity=URGENT"));
        assertTrue(incidentQuery.get().contains("classification=INVESTIGATE"));
    }

    @Test
    void readsPaginatedUebaEvidenceWithoutRequestBodies() throws Exception {
        server.createContext("/api/siem/incidents/case-1/security-events", exchange -> respond(exchange, 200, """
                {"content":[{"id":"event-1","event_timestamp":"2026-09-26T09:05:00",
                "event_type":"AUTH","action":"LOGIN","outcome":"FAILURE",
                "source_ip":"203.0.113.55","route_group":"auth","demo_label":"ABNORMAL"}],
                "page":0,"size":200,"total_elements":136,"total_pages":1,"has_next":false}
                """, null));
        server.createContext("/api/siem/incidents/case-1/behavior-windows", exchange -> respond(exchange, 200, """
                {"content":[{"id":"window-1","account_id":"customer-1",
                "window_start":"2026-09-26T09:00:00","window_end":"2026-09-26T09:15:00",
                "event_count":136,"baseline_established":true,
                "features":{"failed_login_count":6.0},"score_status":"SCORED_MODEL",
                "risk_score":80,"demo_label":"ABNORMAL"}],
                "page":0,"size":20,"total_elements":1,"total_pages":1,"has_next":false}
                """, null));
        server.createContext("/api/siem/incidents/case-1/security-logs", exchange -> respond(exchange, 200, """
                [{"id":"elastic-1","index":"logs-flare.security-lab",
                "source":{"source":{"ip":"81.2.69.142",
                "geo":{"country_name":"United Kingdom","city_name":"London"}}}}]
                """, null));
        SiemApiClient client = new SiemApiClient(baseUrl);
        var events = client.incidentSecurityEvents("case-1").get(3, TimeUnit.SECONDS);
        var windows = client.incidentBehaviorWindows("case-1").get(3, TimeUnit.SECONDS);
        var elastic = client.incidentSecurityLogs("case-1").get(3, TimeUnit.SECONDS);
        assertEquals(136, events.totalElements());
        assertEquals("FAILURE", events.content().getFirst().outcome());
        assertEquals(6.0, windows.content().getFirst().features().get("failed_login_count"));
        assertEquals("logs-flare.security-lab", elastic.getFirst().index());
    }

    @Test
    void retainsOperationalFaultTelemetryWithoutTurningItIntoAnAttackVerdict() throws Exception {
        server.createContext("/api/siem/incidents/case-503/security-events", exchange -> respond(exchange, 200, """
                {"content":[{"id":"event-503","event_type":"HTTP_REQUEST","action":"REQUEST",
                "outcome":"FAILURE","http_status":503,"demo_label":"ABNORMAL"}],
                "page":0,"size":200,"total_elements":1,"total_pages":1,"has_next":false}
                """, null));
        server.createContext("/api/siem/incidents/case-503/behavior-windows", exchange -> respond(exchange, 200, """
                {"content":[{"id":"window-503","account_id":"customer-1","event_count":25,
                "baseline_established":true,"features":{"http_5xx_count":25.0,"failed_login_count":0.0,
                "new_ip_flag":0.0,"new_user_agent_flag":0.0},"score_status":"SCORED_MODEL",
                "risk_score":95,"anomaly_percentile":99.9,"risk_reasons":"High anomaly percentile",
                "personal_feature_schema_version":4,"scored_feature_schema_version":4,"demo_label":"ABNORMAL"}],
                "page":0,"size":20,"total_elements":1,"total_pages":1,"has_next":false}
                """, null));
        SiemApiClient client = new SiemApiClient(baseUrl);
        var events = client.incidentSecurityEvents("case-503").get(3, TimeUnit.SECONDS);
        var windows = client.incidentBehaviorWindows("case-503").get(3, TimeUnit.SECONDS);
        assertEquals(503, events.content().getFirst().httpStatus());
        assertEquals(25.0, windows.content().getFirst().features().get("http_5xx_count"));
        assertEquals(95, windows.content().getFirst().riskScore());
        assertEquals("High anomaly percentile", windows.content().getFirst().riskReasons());
        String context = com.flarefitness.monitor.ui.BehaviorSignalSummary.describe(windows.content(), events.content());
        assertTrue(context.startsWith("Service-error signal (possible operational fault)"));
        assertTrue(context.contains("not attack confirmation"));
    }

    private void respond(HttpExchange exchange, int status, String body, String cookie) throws IOException {
        if (cookie != null) exchange.getResponseHeaders().add("Set-Cookie", cookie);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
