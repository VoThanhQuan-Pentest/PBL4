package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.SensitiveActionConfirmationService;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;


/** One continuous hour of real HTTP + the fixed numeric worker; synthetic lab accounts only. */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="FLARE_POSTLOGIN_OBSERVE",matches="true")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "server.address=127.0.0.1","siem.enabled=false","siem.ueba.enabled=false","siem.prevention.enabled=false",
    "siem.postlogin.enabled=true","siem.security-events.enabled=true","siem.security-events.post-login-enabled=true",
    "management.health.mail.enabled=false","logging.level.AUDIT=OFF","siem.ueba.initial-delay-ms=7200000",
    "siem.security-events.output-file=/tmp/flare-project-observe-events.ndjson",
    "app.sensitive-action-confirmation.enabled=true",
    "app.sensitive-action-confirmation.account-allowlist=project-observe-ready,project-observe-cold,project-observe-ops"})
class PostloginProjectObserveTest extends ContainerizedIntegrationTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired EmailOtpService otp;
    @Autowired SensitiveActionConfirmationRepository actions;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean JavaMailSender mail;
    final Map<String,String> delivered=new ConcurrentHashMap<>();
    static final String CURRENT="ProjectObserveOnly#2026!";
    final java.nio.file.Path output=java.nio.file.Path.of(System.getenv("FLARE_POSTLOGIN_OBSERVE_DIR"));
    int sensitiveAttempts;
    @org.springframework.test.context.DynamicPropertySource
    static void worker(org.springframework.test.context.DynamicPropertyRegistry r) {
        r.add("siem.ueba.url",()->System.getenv("FLARE_POSTLOGIN_WORKER_URL"));
        r.add("siem.ueba.service-token-file",()->System.getenv("FLARE_POSTLOGIN_TOKEN_FILE"));
        r.add("siem.postlogin.manifest-sha256",()->"7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784");
        r.add("siem.postlogin.operator-hold-file",()->System.getenv("FLARE_POSTLOGIN_RUNTIME_HOLD_FILE"));
    }
    void captureMail() {
        doAnswer(invocation->{
            SimpleMailMessage m=invocation.getArgument(0);var match=Pattern.compile("\\b\\d{6}\\b").matcher(m.getText());
            assertThat(match.find()).isTrue();delivered.put(m.getTo()[0],match.group());return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }
    void history(String user) {
        var at=LocalDateTime.now(ZoneOffset.UTC).withMinute(0).withSecond(0).withNano(0).minusHours(1);
        for(int i=0;i<30;i++) jdbc.update("""
            INSERT INTO siem_account_behavior_windows
            (id,account_id,window_start,window_end,feature_schema_version,event_count,request_count,http_4xx_count,http_5xx_count,
            failed_login_count,successful_login_count,sensitive_action_count,distinct_route_group_count,distinct_source_ip_count,
            new_ip_flag,new_user_agent_flag,unusual_hour_flag,baseline_established,score_status,ngay_tao,updated_at,demo_label,source_ip,user_agent_family)
            VALUES (?,?,?,?,1,10,10,0,0,0,0,0,1,1,false,false,false,false,'SCORED_RULE_ONLY',?,?,'NORMAL','127.0.0.1','OTHER')
            """,java.util.UUID.randomUUID().toString(),user,at.minusMinutes(i*15L),at.minusMinutes(i*15L).plusMinutes(15),at,at);
    }
    void scenario(String user,String source,int cycle) {
        int requests=cycle%3==0?0:60,status=cycle%3==1?404:503;
        var at=LocalDateTime.now(ZoneOffset.UTC).minusSeconds(2);
        var categories=com.flarefitness.backend.service.siem.EndpointCategory.values();
        for(int i=0;i<requests;i++) jdbc.update("""
            INSERT INTO siem_security_events
            (id,event_timestamp,actor_user_id,source_ip,event_type,action,outcome,route_group,http_method,http_status,ngay_tao,
            telemetry_contract_version,session_pseudonym,session_issued_at,endpoint_category,demo_label)
            VALUES (?,?,?,?,'HTTP_REQUEST','API_REQUEST','FAILURE','account','GET',?,?,3,?,?,?,'DEMO_ONLY')
            """,java.util.UUID.randomUUID().toString(),at,user,source,status,at,"e".repeat(64),at.minusMinutes(1),categories[i%7].name());
    }
    void publish(String name,Object value) throws Exception {
        var path=output.resolve(name);var temporary=output.resolve("."+name+".pending");
        java.nio.file.Files.deleteIfExists(temporary);
        java.nio.file.Files.writeString(temporary,json.writeValueAsString(value),java.nio.file.StandardOpenOption.CREATE_NEW);
        java.nio.file.Files.setPosixFilePermissions(temporary,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        try(var f=java.nio.channels.FileChannel.open(temporary,java.nio.file.StandardOpenOption.WRITE)){f.force(true);}
        java.nio.file.Files.move(temporary,path,java.nio.file.StandardCopyOption.REPLACE_EXISTING,java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        try(var d=java.nio.channels.FileChannel.open(output,java.nio.file.StandardOpenOption.READ)){d.force(true);}
    }
    boolean paused() throws Exception {
        var p=java.nio.file.Path.of(System.getenv("FLARE_POSTLOGIN_IMPLEMENTATION_HOLD_FILE"));
        return json.readTree(java.nio.file.Files.readString(p)).path("hold_new_units").asBoolean(true);
    }
    @Test @Timeout(4000)
    void continuousProjectObservation() throws Exception {
        captureMail();
        jdbc.update("""
            UPDATE siem_postlogin_policy SET mode='OBSERVE',account_allowlist_json=?,model_manifest_sha256=?,version=version+1
            WHERE id='postlogin-project-limited-v1'
            ""","[\"project-observe-ready\",\"project-observe-cold\",\"project-observe-ops\"]",
            "7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784");
        var accounts=java.util.List.of(fixture("project-observe-ready"),fixture("project-observe-cold"),fixture("project-observe-ops"));
        history(accounts.get(0).getId());history(accounts.get(2).getId());
        var clients=java.util.List.of(new Client(),new Client(),new Client());
        var rows=new java.util.ArrayList<Map<String,Object>>();
        var worker=HttpClient.newHttpClient();
        long started=System.nanoTime(),lastHeartbeat=started,maxGap=0,maxLatency=0;int count=0,batches=0;
        String began=java.time.Instant.now().toString();
        try {
            for(int i=0;i<3;i++)login(clients.get(i),accounts.get(i));
            while(true) {
                long elapsed=(System.nanoTime()-started)/1_000_000_000L;
                if(paused()) {
                    publish("observe-result.private.json",Map.of("status","PROJECT_OBSERVE_PAUSED_NO_DEPLOY","evaluations",count,
                        "continuous_seconds",elapsed,"sensitive_http_attempts",sensitiveAttempts));
                    org.junit.jupiter.api.Assumptions.abort("Operator pause; this epoch does not qualify.");
                }
                var health=worker.send(HttpRequest.newBuilder(URI.create(System.getenv("FLARE_POSTLOGIN_WORKER_URL")+"/health"))
                    .timeout(Duration.ofSeconds(2)).GET().build(),HttpResponse.BodyHandlers.ofString());
                assertThat(health.statusCode()).isEqualTo(200);
                assertThat(json.readTree(health.body()).path("postlogin").path("available").asBoolean()).isTrue();
                long heartbeat=System.nanoTime();maxGap=Math.max(maxGap,(heartbeat-lastHeartbeat)/1_000_000_000L);lastHeartbeat=heartbeat;
                if(elapsed>=batches*360L && batches<=10) {
                    // Three real confirmation attempts per challenge, one batch every six minutes.
                    // Rotating three accounts means at most four sends/email/hour, retaining the real five-send cap.
                    int ordinal=batches%3;var account=accounts.get(ordinal);var client=clients.get(ordinal);
                    scenario(account.getId(),client.localAddress.getHostAddress(),batches);
                    var challenge=body(send(client,"POST","/api/profile/action-confirmations",Map.of("operation","PASSWORD_CHANGE",
                        "password",Map.of("current_password",CURRENT,"new_password","UnusedProposedChange#2026!","confirm_password","UnusedProposedChange#2026!")),200));
                    String id=challenge.path("id").asText();
                    for(int attempt=0;attempt<3;attempt++) {
                    String request=java.util.UUID.randomUUID().toString();
                    long before=System.nanoTime();
                    send(client,"POST","/api/profile/action-confirmations/"+id+"/execute",
                        Map.of("confirmation_code",wrong(delivered.get(account.getEmail())),"request_id",request),400);
                    long latency=(System.nanoTime()-before)/1_000_000L;maxLatency=Math.max(maxLatency,latency);
                    var row=jdbc.queryForMap("SELECT id,decision,context_class,normal_percentile,baseline_established,trusted_window_count,mode,outcome,feature_snapshot_json FROM siem_postlogin_decisions WHERE request_id=?",request);
                    assertThat(row.get("mode")).isEqualTo("OBSERVE");assertThat(row.get("outcome")).isEqualTo("OTP_REJECTED");
                    assertThat(row.get("decision")).isNotEqualTo("UNDETERMINED");assertThat(latency).isLessThan(2000);
                    row.put("case_index",count);row.put("elapsed_seconds",elapsed);row.put("execute_latency_ms",latency);rows.add(row);count++;
                    publish("observe-evaluations.private.json",rows);
                    }
                    batches++;
                }
                assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_holds WHERE expires_at>UTC_TIMESTAMP(6)",Integer.class)).isZero();
                publish("observe-progress.private.json",Map.of("status","OBSERVING","started_at_utc",began,"continuous_seconds",elapsed,
                    "evaluations",count,"target_evaluations",33,"required_seconds",3600,"sensitive_http_attempts",sensitiveAttempts,"max_heartbeat_gap_seconds",maxGap));
                if(elapsed>=3600 && count>=33)break;
                Thread.sleep(5000);
            }
            for(var account:accounts)assertThat(users.findById(account.getId()).orElseThrow().getPassword()).isEqualTo(account.getPassword());
            assertThat(maxGap).isLessThanOrEqualTo(20);
            publish("observe-result.private.json",Map.of("status","PROJECT_ONE_HOUR_OBSERVE_PASS","started_at_utc",began,
                "continuous_seconds",(System.nanoTime()-started)/1_000_000_000L,"evaluations",count,"sensitive_http_attempts",sensitiveAttempts,
                "maximum_execute_latency_ms",maxLatency,"maximum_heartbeat_gap_seconds",maxGap,"new_fits",0,
                "scope","PROJECT_LIMITED_CONTROLLED_HTTP_SYNTHETIC_CONTEXT","strict_production_qualified",false));
        } finally { clients.forEach(Client::close);worker.close(); }
    }
    User fixture(String id) {
        String email = id + "@example.test";
        otp.sendOtp(EmailOtpService.PURPOSE_REGISTER, email);
        otp.verifyOtp(EmailOtpService.PURPOSE_REGISTER, email, delivered.get(email));
        User user = new User(); user.setId(id); user.setUsername(id); user.setEmail(email);
        user.setEmailVerifiedAt(LocalDateTime.now(ZoneOffset.UTC).minusSeconds(1));
        user.setPassword(encoder.encode(CURRENT)); user.setRole("CUSTOMER"); user.setHoTen("Confirmation lab owner");
        user.setStatus("Hoat dong"); user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return users.saveAndFlush(user);
    }
    void login(Client client, User user) throws Exception {
        send(client, "POST", "/api/auth/login", Map.of("username", user.getUsername(), "password", CURRENT), 200);
    }
    JsonNode body(HttpResponse<String> response) throws Exception { return json.readTree(response.body()); }
    String wrong(String code) { return "000000".equals(code) ? "111111" : "000000"; }
    String csrf(Client client) throws Exception {
        var response = raw(client, "GET", "/api/auth/csrf", null, null);
        assertThat(response.statusCode()).isEqualTo(200);
        return body(response).path("token").asText();
    }
    HttpResponse<String> send(Client client, String method, String path, Object payload, int expected) throws Exception {
        var response = raw(client, method, path, payload, payload == null ? null : csrf(client));
        // Do not print request/response bodies: they may include OTPs or private profile data.
        assertThat(response.statusCode()).as("%s %s", method, path).isEqualTo(expected);
        return response;
    }
    HttpResponse<String> raw(Client client, String method, String path, Object payload, String csrf) throws Exception {
        if (path.startsWith("/api/profile/action-confirmations") && !method.equals("GET")) sensitiveAttempts++;
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(15));
        if (payload == null) request.method(method, HttpRequest.BodyPublishers.noBody());
        else request.header("Content-Type", "application/json").header("X-XSRF-TOKEN", csrf)
                .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(payload)));
        return client.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    static class Client implements AutoCloseable {
        static final java.util.concurrent.atomic.AtomicInteger NEXT_ADDRESS = new java.util.concurrent.atomic.AtomicInteger(1);
        final java.net.InetAddress localAddress;
        final HttpClient http;
        Client() throws java.net.UnknownHostException {
            this(address(NEXT_ADDRESS.getAndIncrement()));
        }
        Client(java.net.InetAddress address) {
            localAddress = address;
            http = HttpClient.newBuilder().localAddress(address)
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
        }
        static java.net.InetAddress address(int ordinal) throws java.net.UnknownHostException {
            return java.net.InetAddress.getByAddress(new byte[]{127, 2, (byte)(ordinal / 256), (byte)(ordinal % 256)});
        }
        public void close() { http.close(); }
    }
}
