package com.flarefitness.monitor.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.flarefitness.monitor.model.SiemModels;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class SiemApiClient {
    private final URI baseUri;
    private final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER);
    private final HttpClient httpClient = HttpClient.newBuilder()
            .cookieHandler(cookies)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .setNodeFactory(com.fasterxml.jackson.databind.node.JsonNodeFactory.withExactBigDecimals(true));
    private volatile String csrfToken;
    private final java.util.function.LongSupplier activityClock;
    private volatile long lastUserActivity = Long.MIN_VALUE;
    public void recordUserActivity() { lastUserActivity = activityClock.getAsLong(); }
    private boolean recentUserActivity() {
        long last = lastUserActivity;
        if (last == Long.MIN_VALUE) return false;
        long age = activityClock.getAsLong() - last;
        return age >= 0 && age <= java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
    }
    private Runnable onSessionExpired=()->{};
    public void setOnSessionExpired(Runnable callback) { onSessionExpired=callback; }
    public void clearSession() { cookies.getCookieStore().removeAll();csrfToken=null;lastUserActivity=Long.MIN_VALUE; }
    public static String configuredOrigin() {
        String property=System.getProperty("flare.soc.serverOrigin");
        if(property!=null && !property.isBlank()) return property;
        String environment=System.getenv("FLARE_SOC_SERVER_ORIGIN");
        return environment==null || environment.isBlank()?"http://127.0.0.1:8089":environment;
    }
    public CompletableFuture<List<Map<String,Object>>> authShadowAssessments(String incident,String account,LocalDateTime from,LocalDateTime to) {
        String path="/api/siem/shadow-assessments?size=50&from="+encode(from.toString())+"&to="+encode(to.toString());
        if(incident!=null&&!incident.isBlank())path+="&incidentId="+encode(incident);
        if(account!=null&&!account.isBlank())path+="&accountId="+encode(account);
        return get(path,new TypeReference<>(){});
    }
    public CompletableFuture<List<Map<String,Object>>> authCorrelationHistory(){return get("/api/siem/auth-correlation/policy/history",new TypeReference<>(){});}
    public CompletableFuture<SiemModels.AuthCorrelationPolicy> authCorrelationPolicy() {return get("/api/siem/auth-correlation/policy",SiemModels.AuthCorrelationPolicy.class);}
    public CompletableFuture<SiemModels.AuthCorrelationPolicy> changeAuthCorrelationPolicy(SiemModels.AuthCorrelationPolicy policy,String mode,String reason,String request) {
        return write("PUT","/api/siem/auth-correlation/policy",Map.of("mode",mode,"expected_version",policy.version(),"reason",reason,"request_id",request),SiemModels.AuthCorrelationPolicy.class);
    }
    public CompletableFuture<SiemModels.Page<SiemModels.InvestigationQueueEntry>> queueSummaries(List<String> ids) {
        if(ids.isEmpty())return CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(),0,50,0,0,false));
        return get("/api/siem/investigation-queue?includeEventTime=true&ids="+encode(String.join(",",ids)),new TypeReference<>(){});
    }
    public CompletableFuture<SiemModels.InvestigationMetrics> investigationMetrics(LocalDateTime from,LocalDateTime to) {
        return get("/api/siem/investigation-metrics?from="+encode(from.toString())+"&to="+encode(to.toString()),SiemModels.InvestigationMetrics.class);
    }
    public CompletableFuture<SiemModels.InvestigationSummary> investigationSummary(String incident) {
        return get("/api/siem/incidents/"+encode(incident)+"/investigation-summary?includeEventTime=true",SiemModels.InvestigationSummary.class);
    }
    public CompletableFuture<SiemModels.TimelinePage> incidentTimeline(String incident,String types,boolean related,String cursor) {
        return timelineRequest(incident,types,related,cursor,null,null);
    }
    public CompletableFuture<SiemModels.TimelinePage> incidentTimeline(String incident,String types,boolean related,String cursor,LocalDateTime from,LocalDateTime to) {
        if(from==null&&to==null)return incidentTimeline(incident,types,related,cursor);
        return timelineRequest(incident,types,related,cursor,from,to);
    }
    private CompletableFuture<SiemModels.TimelinePage> timelineRequest(String incident,String types,boolean related,String cursor,LocalDateTime from,LocalDateTime to) {
        String path="/api/siem/incidents/"+encode(incident)+"/timeline?size=50&includeRelated="+related;
        if(types!=null&&!types.isBlank())path+="&types="+encode(types);
        if(cursor!=null)path+="&cursor="+encode(cursor);
        if(from!=null&&to!=null)path+="&from="+encode(from.toString())+"&to="+encode(to.toString());
        return get(path,SiemModels.TimelinePage.class);
    }
    public CompletableFuture<SiemModels.EvidencePage> evidence(LocalDateTime from,LocalDateTime to,
            String dataset,String trace,String ip,String account,String cursor) {
        String path="/api/siem/evidence?from="+encode(from.toString())+"&to="+encode(to.toString())+"&size=50";
        if(dataset!=null && !dataset.isBlank())path+="&dataset="+encode(dataset);
        if(trace!=null && !trace.isBlank())path+="&traceId="+encode(trace);
        if(ip!=null && !ip.isBlank())path+="&ip="+encode(ip);
        if(account!=null && !account.isBlank())path+="&accountId="+encode(account);
        if(cursor!=null)path+="&cursor="+encode(cursor);
        return get(path,SiemModels.EvidencePage.class);
    }
    public CompletableFuture<SiemModels.EvidencePage> incidentEvidence(String id,String cursor) {
        return get("/api/siem/incidents/"+encode(id)+"/evidence?size=50"+(cursor==null?"":"&cursor="+encode(cursor)),SiemModels.EvidencePage.class);
    }
    public CompletableFuture<SiemModels.Note> addNote(String id,String note) {
        return post("/api/siem/incidents/"+encode(id)+"/notes",Map.of("content",note),SiemModels.Note.class);
    }
    public CompletableFuture<SiemModels.Incident> createIncident(String title,List<SiemModels.EvidenceItem> events) {
        var refs=events.stream().map(e->Map.of("index",e.elkHit().path("_index").asText(),"id",e.elkHit().path("_id").asText())).toList();
        return post("/api/siem/incidents",Map.of("title",title,"events",refs),SiemModels.Incident.class);
    }
    public CompletableFuture<List<SiemModels.ContainmentAction>> containment(String id) {
        return get("/api/siem/incidents/"+encode(id)+"/containment-actions",new TypeReference<>(){});
    }
    public CompletableFuture<SiemModels.ContainmentAction> isolate(SiemModels.Incident incident,String reason,String duration,String requestId) {
        return post("/api/siem/incidents/"+encode(incident.id())+"/containment-actions",Map.of("request_id",requestId,"expected_version",incident.version(),"reason",reason,"duration",duration),SiemModels.ContainmentAction.class);
    }
    public CompletableFuture<SiemModels.ContainmentAction> release(SiemModels.ContainmentAction action,String reason,String requestId) {
        return post("/api/siem/containment-actions/"+encode(action.id())+"/release",Map.of("request_id",requestId,"expected_version",action.version(),"reason",reason),SiemModels.ContainmentAction.class);
    }
    public CompletableFuture<SiemModels.BlockWorkspace> blocksWithLedger() {return blocksWithLedger(0);}
    public CompletableFuture<SiemModels.BlockWorkspace> blocksWithLedger(int page) {return get("/api/siem/prevention/blocks?page="+page+"&size=50",SiemModels.BlockWorkspace.class);}
    public CompletableFuture<SiemModels.IpBlock> revokeBlock(SiemModels.IpBlock block,String reason,String outcome,String requestId) {
        return post("/api/siem/prevention/blocks/"+encode(block.id())+"/revoke",Map.of("expected_version",block.version(),"reason",reason,"outcome",outcome,"request_id",requestId),SiemModels.IpBlock.class);
    }

    public SiemApiClient(String baseUrl) { this(baseUrl, System::nanoTime); }

    SiemApiClient(String baseUrl, java.util.function.LongSupplier activityClock) {
        this.activityClock = java.util.Objects.requireNonNull(activityClock);
        String normalized = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        URI candidate;
        try {
            candidate = URI.create(normalized);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Server URL must be an HTTP(S) origin, for example http://127.0.0.1:8088");
        }
        boolean validOrigin = ("http".equals(candidate.getScheme()) || "https".equals(candidate.getScheme()))
                && candidate.getHost() != null && candidate.getUserInfo()==null
                && (candidate.getPath() == null || candidate.getPath().isEmpty())
                && candidate.getQuery() == null
                && candidate.getFragment() == null;
        if (!validOrigin) {
            throw new IllegalArgumentException("Server URL must be an HTTP(S) origin, for example http://127.0.0.1:8088");
        }
        boolean loopback = "localhost".equalsIgnoreCase(candidate.getHost())
                || "127.0.0.1".equals(candidate.getHost())
                || "::1".equals(candidate.getHost()) || "[::1]".equals(candidate.getHost());
        if ("http".equals(candidate.getScheme()) && !loopback) {
            throw new IllegalArgumentException("Remote SIEM servers must use HTTPS.");
        }
        this.baseUri = candidate;
    }

    public CompletableFuture<SiemModels.LoginAttempt> beginLogin(String username, String password) {
        return refreshCsrf().thenCompose(ignored -> raw("POST", "/api/auth/login",
                json(Map.of("username", username, "password", password)), true))
                .thenCompose(response -> {
                    if (response.statusCode() == 202) {
                        var challenge = read(response.body(), SiemModels.LoginChallenge.class);
                        if (challenge.challengeId() == null || challenge.challengeId().isBlank()) {
                            throw new IllegalStateException("Missing login challenge");
                        }
                        return CompletableFuture.completedFuture(new SiemModels.LoginAttempt(null, challenge));
                    }
                    var session = read(response.body(), SiemModels.LoginResponse.class);
                    recordUserActivity();
                    return refreshCsrf().thenApply(ignored -> new SiemModels.LoginAttempt(session, null));
                });
    }

    public CompletableFuture<SiemModels.LoginResponse> login(String username, String password) {
        return beginLogin(username, password).thenApply(attempt -> {
            if (attempt.challenge() != null) throw new IllegalStateException("OTP login verification required");
            return attempt.session();
        });
    }

    public CompletableFuture<SiemModels.LoginResponse> verifyLoginOtp(String challengeId, String otpCode) {
        return post("/api/auth/login/otp", Map.of("challenge_id", challengeId, "otp_code", otpCode), SiemModels.LoginResponse.class)
                .thenCompose(response -> {
                    recordUserActivity();
                    return refreshCsrf().thenApply(ignored -> response);
                });
    }

    /** Revoke the server session, then discard all local cookies even if the request fails. */
    public CompletableFuture<Void> logout() {
        return refreshCsrf()
                .thenCompose(ignored -> raw("POST", "/api/auth/logout", null, true))
                .thenAccept(ignored -> { })
                .whenComplete((ignored, failure) -> {
                    clearSession();
                });
    }

    public CompletableFuture<SiemModels.Overview> overview() {
        return get("/api/siem/overview", SiemModels.Overview.class);
    }

    public CompletableFuture<SiemModels.PostloginPolicy> postloginPolicy() {
        return get("/api/siem/postlogin-policy",SiemModels.PostloginPolicy.class);
    }
    public CompletableFuture<SiemModels.Page<SiemModels.PostloginDecision>> postloginDecisions(String incidentId,int page) {
        return get("/api/siem/postlogin-decisions?page="+page+"&size=50"
                +(incidentId==null?"":"&incidentId="+encode(incidentId)),new TypeReference<>(){});
    }
    public CompletableFuture<SiemModels.PostloginDetail> postloginDecision(String id) {
        return get("/api/siem/postlogin-decisions/"+encode(id),SiemModels.PostloginDetail.class);
    }
    public CompletableFuture<SiemModels.PostloginDetail> releasePostloginHold(String id,long version,String reason) {
        return post("/api/siem/postlogin-decisions/"+encode(id)+"/release",
                Map.of("expected_version",version,"reason",reason),SiemModels.PostloginDetail.class);
    }
    public CompletableFuture<SiemModels.PostloginDetail> reviewPostloginDecision(String id,long version,String verdict,String reason) {
        return post("/api/siem/postlogin-decisions/"+encode(id)+"/review",
                Map.of("expected_version",version,"verdict",verdict,"reason",reason),SiemModels.PostloginDetail.class);
    }

    public CompletableFuture<SiemModels.DashboardSummary> dashboardSummary(
            LocalDateTime from, LocalDateTime to) {
        String path = "/api/siem/dashboard-summary?from=" + encode(from.toString())
                + "&to=" + encode(to.toString());
        return get(path, SiemModels.DashboardSummary.class);
    }

    public CompletableFuture<SiemModels.Status> status() {
        return get("/api/siem/status", SiemModels.Status.class);
    }

    public CompletableFuture<SiemModels.UebaStatus> uebaStatus() {
        return get("/api/siem/ueba/status", SiemModels.UebaStatus.class);
    }

    public CompletableFuture<SiemModels.UebaTrainingJob> startUebaTraining(
            LocalDateTime from, LocalDateTime to) {
        return post("/api/siem/ueba/training-jobs", Map.of("from", from, "to", to),
                SiemModels.UebaTrainingJob.class);
    }

    public CompletableFuture<List<SiemModels.UebaRecipe>> uebaRecipes() {
        return get("/api/siem/ueba/recipes", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.UebaTrainingJob> startUebaRecipe(SiemModels.UebaRecipe recipe) {
        return post("/api/siem/ueba/training-jobs", Map.of("from", recipe.from(), "to", recipe.to(), "recipe_id", recipe.recipeId()),
                SiemModels.UebaTrainingJob.class);
    }

    public CompletableFuture<SiemModels.UebaTrainingJob> evaluateUebaModel(String version, String dataset) {
        return post("/api/siem/ueba/models/" + encode(version) + "/evaluate",
                dataset == null ? Map.of() : Map.of("dataset_id", dataset), SiemModels.UebaTrainingJob.class);
    }

    public CompletableFuture<SiemModels.UebaTrainingJob> uebaTrainingJob(String id) {
        return get("/api/siem/ueba/training-jobs/" + encode(id), SiemModels.UebaTrainingJob.class);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.UebaTrainingJob>> uebaTrainingJobs() {
        return uebaTrainingJobs(0, 20);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.UebaTrainingJob>> uebaTrainingJobs(int page, int size) {
        validateUebaPage(page, size);
        return get("/api/siem/ueba/training-jobs?page=" + page + "&size=" + size, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.UebaShadowRun> startUebaShadow(String version) {
        return post("/api/siem/ueba/shadow-runs", Map.of("model_version", version), SiemModels.UebaShadowRun.class);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.UebaShadowRun>> uebaShadowRuns(int page, int size) {
        validateUebaPage(page, size);
        return get("/api/siem/ueba/shadow-runs?page=" + page + "&size=" + size, new TypeReference<>() { });
    }

    private static void validateUebaPage(int page, int size) {
        if (page < 0 || size < 1 || size > 50) throw new IllegalArgumentException("Invalid UEBA page.");
    }

    public CompletableFuture<SiemModels.UebaTrainingJob> activateUebaModel(String version) {
        return post("/api/siem/ueba/models/" + encode(version) + "/activate", Map.of(),
                SiemModels.UebaTrainingJob.class);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.AttackSignature>> signatures() {
        return get("/api/siem/signatures?page=0&size=100", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.AttackSignature> createSignature(
            String kind, String method, String scope, String value, String severity) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("kind", kind);
        body.put("http_method", blankToNull(method));
        body.put("path_prefix", blankToNull(scope));
        body.put("match_value", blankToNull(value));
        body.put("severity", severity);
        return post("/api/siem/signatures", body, SiemModels.AttackSignature.class);
    }

    public CompletableFuture<SiemModels.SignatureTestResult> testSignature(
            SiemModels.AttackSignature signature, List<Map<String, Object>> fixtures) {
        return post("/api/siem/signatures/" + encode(signature.id())
                        + "/test?version=" + signature.version(),
                Map.of("fixtures", fixtures), SiemModels.SignatureTestResult.class);
    }

    public CompletableFuture<SiemModels.SignatureTestResult> testDefaultSignature(
            SiemModels.AttackSignature signature) {
        return post("/api/siem/signatures/" + encode(signature.id())
                        + "/test-default?version=" + signature.version(),
                Map.of(), SiemModels.SignatureTestResult.class);
    }

    public CompletableFuture<SiemModels.AttackSignature> activateSignature(SiemModels.AttackSignature value) {
        return post("/api/siem/signatures/" + encode(value.id())
                        + "/activate?version=" + value.version(),
                Map.of(), SiemModels.AttackSignature.class);
    }

    public CompletableFuture<SiemModels.AttackSignature> disableSignature(SiemModels.AttackSignature value) {
        return post("/api/siem/signatures/" + encode(value.id())
                        + "/disable?version=" + value.version(),
                Map.of(), SiemModels.AttackSignature.class);
    }

    public CompletableFuture<SiemModels.PreventionStatus> preventionStatus() {
        return get("/api/siem/prevention/status", SiemModels.PreventionStatus.class);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.IpBlock>> ipBlocks() {
        return get("/api/siem/ip-blocks?page=0&size=100", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.IpBlock> createIpBlock(
            String ip, String reason, long minutes, String incidentId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ip_address", ip);
        body.put("reason", reason);
        body.put("duration_minutes", minutes);
        body.put("incident_id", blankToNull(incidentId));
        return post("/api/siem/ip-blocks", body, SiemModels.IpBlock.class);
    }

    public CompletableFuture<SiemModels.IpBlock> revokeIpBlock(SiemModels.IpBlock value) {
        return post("/api/siem/ip-blocks/" + encode(value.id())
                        + "/revoke?version=" + value.version(),
                Map.of(), SiemModels.IpBlock.class);
    }

    public CompletableFuture<List<SiemModels.IpIntelligence>> ipIntelligence(String ip) {
        return get("/api/siem/ip-intelligence?ip=" + encode(ip), new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.IpIntelligence>> incidentIpIntelligence(String incidentId) {
        return get("/api/siem/incidents/" + encode(incidentId) + "/ip-intelligence",
                new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.IpIntelligence>> demoIpIntelligence() {
        return get("/api/siem/ip-intelligence/demo", new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.IpIntelligence>> seedDemoIpIntelligence() {
        return post("/api/siem/ip-intelligence/demo", Map.of(), new TypeReference<>() { });
    }

    public CompletableFuture<Map<String, String>> requestIpLookup(String ip, String reason) {
        return post("/api/siem/ip-intelligence/lookup?ip=" + encode(ip)
                        + "&reason=" + encode(reason),
                Map.of(), new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.WatchAccount>> watchlist(
            LocalDateTime from, LocalDateTime to) {
        return watchlist(from, to, "RISK", 0, 50);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.WatchAccount>> watchlist(
            LocalDateTime from, LocalDateTime to, String view, int page, int size) {
        String path = "/api/siem/accounts/watchlist?from=" + encode(from.toString())
                + "&to=" + encode(to.toString()) + "&view=" + encode(view)
                + "&page=" + page + "&size=" + size;
        return get(path, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.BehaviorWindow>> accountBehavior(
            String accountId, LocalDateTime from, LocalDateTime to) {
        String path = "/api/siem/accounts/" + encode(accountId) + "/behavior?from=" + encode(from.toString())
                + "&to=" + encode(to.toString()) + "&page=0&size=100";
        return get(path, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.SessionRevocationResult> revokeCustomerSessions(
            SiemModels.Incident incident, String reason, String requestId) {
        String idempotencyKey = requestId == null ? UUID.randomUUID().toString() : requestId;
        return post("/api/siem/incidents/" + encode(incident.id()) + "/response-actions",
                Map.of("expected_version", incident.version(), "request_id", idempotencyKey,
                        "reason", reason.trim()), SiemModels.SessionRevocationResult.class);
    }

    public CompletableFuture<SiemModels.Page<SiemModels.Incident>> incidents(String query) {
        String path = "/api/siem/incidents?page=0&size=100&includeAssignedAnalyst=true";
        if (query != null && !query.isBlank()) {
            path += "&q=" + URLEncoder.encode(query.trim(), StandardCharsets.UTF_8);
        }
        return get(path, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.Incident>> incidents(SiemModels.IncidentQuery query) {
        StringBuilder path = new StringBuilder("/api/siem/incidents?page=")
                .append(query.page()).append("&size=").append(query.size()).append("&includeAssignedAnalyst=true");
        appendQuery(path, "q", query.query());
        appendQuery(path, "status", query.status());
        appendQuery(path, "severity", query.severity());
        appendQuery(path, "classification", query.classification());
        appendQuery(path, "scope", query.scope());
        appendQuery(path, "sort", query.sort());
        appendQuery(path, "queueTier", query.queueTier());
        appendQuery(path, "origin", query.origin());
        appendQuery(path, "targetUserId", query.targetUserId());
        if (query.mine()) path.append("&mine=true");
        if (query.from() != null) appendQuery(path, "from", query.from().toString());
        if (query.to() != null) appendQuery(path, "to", query.to().toString());
        return get(path.toString(), new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.IncidentDetail> incident(String id) {
        return get("/api/siem/incidents/" + encode(id) + "?includeAssignedAnalyst=true", SiemModels.IncidentDetail.class);
    }

    public CompletableFuture<List<SiemModels.AlertRef>> incidentAlerts(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/alerts", new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.ElasticDocument>> incidentLogs(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/logs", new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.ElasticDocument>> incidentSecurityLogs(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/security-logs", new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.ElasticDocument>> incidentPreventionLogs(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/prevention-logs", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.BehaviorWindow>> incidentBehaviorWindows(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/behavior-windows?page=0&size=20",
                new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.SecurityEventEvidence>> incidentSecurityEvents(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/security-events?page=0&size=200",
                new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.History>> incidentHistory(String id) {
        return get("/api/siem/incidents/" + encode(id) + "/history", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Incident> updateIncident(
            SiemModels.Incident incident, String status, String conclusion, String note, boolean investigateOverride) {
        return patch("/api/siem/incidents/" + encode(incident.id()), Map.of(
                "version", incident.version(),
                "status", status,
                "conclusion", conclusion,
                "note", note == null ? "" : note,
                "manual_investigate_override", investigateOverride), SiemModels.Incident.class);
    }

    public CompletableFuture<SiemModels.Incident> verifyResponse(SiemModels.Incident incident,String reason,String response,String recovery,String requestId) {
        return post("/api/siem/incidents/"+encode(incident.id())+"/response-checks",Map.of("expected_version",incident.version(),"reason",reason,"response_result",response,"recovery_result",recovery,"request_id",requestId),SiemModels.Incident.class);
    }
    public CompletableFuture<SiemModels.Incident> transitionIncident(
            SiemModels.Incident incident, String action, String reason, String conclusion) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("expected_version", incident.version());
        body.put("action", action);
        if (reason != null && !reason.isBlank()) body.put("reason", reason.trim());
        if (conclusion != null) body.put("conclusion", conclusion);
        return post("/api/siem/incidents/" + encode(incident.id()) + "/transitions",
                body, SiemModels.Incident.class);
    }

    public CompletableFuture<List<SiemModels.ElasticDocument>> logs(LocalDateTime from, LocalDateTime to) {
        String path = "/api/siem/logs?from=" + encode(from.toString()) + "&to=" + encode(to.toString()) + "&size=100";
        return get(path, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.GeoSummary> geoSummary(LocalDateTime from,LocalDateTime to) {
        return get("/api/siem/geo/summary?from="+encode(from.toString())+"&to="+encode(to.toString()),SiemModels.GeoSummary.class);
    }
    public CompletableFuture<List<SiemModels.GeoBucket>> geo(LocalDateTime from, LocalDateTime to) {
        String path = "/api/siem/geo?from=" + encode(from.toString()) + "&to=" + encode(to.toString());
        return get(path, new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.Page<SiemModels.History>> history() {
        return get("/api/siem/history?page=0&size=100", new TypeReference<>() { });
    }

    public CompletableFuture<List<SiemModels.TestWindow>> testWindows() {
        return get("/api/siem/test-windows", new TypeReference<>() { });
    }

    public CompletableFuture<SiemModels.TestWindow> createTestWindow(
            String name, String sourceIp, String serviceId, LocalDateTime startsAt, LocalDateTime endsAt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("source_ip", sourceIp == null || sourceIp.isBlank() ? null : sourceIp.trim());
        body.put("service_id", serviceId == null || serviceId.isBlank() ? null : serviceId.trim());
        body.put("starts_at", startsAt);
        body.put("ends_at", endsAt);
        return post("/api/siem/test-windows", body, SiemModels.TestWindow.class);
    }

    public CompletableFuture<SiemModels.TestWindow> endTestWindow(SiemModels.TestWindow window) {
        String path = "/api/siem/test-windows/" + encode(window.id()) + "/end?version=" + window.version();
        return refreshCsrf().thenCompose(ignored -> raw("PATCH", path, null, true))
                .thenApply(response -> read(response.body(), SiemModels.TestWindow.class));
    }

    private CompletableFuture<Void> refreshCsrf() {
        return raw("GET", "/api/auth/csrf", null, false).thenAccept(response -> {
            try {
                csrfToken = objectMapper.readTree(response.body()).path("token").asText();
            } catch (Exception exception) {
                throw new IllegalStateException("Cannot read CSRF response", exception);
            }
        });
    }

    private <T> CompletableFuture<T> get(String path, Class<T> type) {
        return raw("GET", path, null, false).thenApply(response -> read(response.body(), type));
    }

    private <T> CompletableFuture<T> get(String path, TypeReference<T> type) {
        return raw("GET", path, null, false).thenApply(response -> read(response.body(), type));
    }

    private <T> CompletableFuture<T> post(String path, Object body, Class<T> type) {
        return write("POST", path, body, type);
    }

    private <T> CompletableFuture<T> post(String path, Object body, TypeReference<T> type) {
        return refreshCsrf().thenCompose(ignored -> raw("POST", path, json(body), true))
                .thenApply(response -> read(response.body(), type));
    }

    private <T> CompletableFuture<T> patch(String path, Object body, Class<T> type) {
        return write("PATCH", path, body, type);
    }

    private <T> CompletableFuture<T> write(String method, String path, Object body, Class<T> type) {
        return refreshCsrf().thenCompose(ignored -> raw(method, path, json(body), true))
                .thenApply(response -> read(response.body(), type));
    }

    private CompletableFuture<HttpResponse<String>> raw(String method, String path, String body, boolean csrf) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseUri.resolve(path))
                .timeout(Duration.ofSeconds(12))
                .header("Accept", "application/json");
        if (csrf && csrfToken != null) builder.header("X-XSRF-TOKEN", csrfToken);
        if (recentUserActivity()) builder.header("X-User-Activity", "1");
        if (body == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        return httpClient.sendAsync(builder.build(), HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        if(response.statusCode()==401) { clearSession();onSessionExpired.run(); }
                        throw apiError(response.statusCode(), response.body());
                    }
                    return response;
                });
    }

    private SiemApiException apiError(int status, String body) {
        try {
            JsonNode error = objectMapper.readTree(body);
            return new SiemApiException(status, error.path("message").asText("Server returned " + status));
        } catch (Exception ignored) {
            return new SiemApiException(status, "Server returned " + status);
        }
    }

    private String json(Object body) {
        try {
            return objectMapper.writeValueAsString(body);
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot encode request", exception);
        }
    }

    private <T> T read(String body, Class<T> type) {
        try {
            return objectMapper.readValue(body, type);
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot decode server response", exception);
        }
    }

    private <T> T read(String body, TypeReference<T> type) {
        try {
            return objectMapper.readValue(body, type);
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot decode server response", exception);
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private void appendQuery(StringBuilder path, String name, String value) {
        if (value == null || value.isBlank()) return;
        path.append('&').append(name).append('=').append(encode(value.trim()));
    }
}
