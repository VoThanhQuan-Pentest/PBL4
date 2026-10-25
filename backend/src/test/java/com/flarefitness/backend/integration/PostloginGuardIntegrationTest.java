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

/** Isolated MySQL/Redis HTTP proof of the limited action guard; no live mail or model fits. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=false", "siem.prevention.enabled=false",
        "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
        "management.health.mail.enabled=false", "logging.level.AUDIT=OFF", "siem.postlogin.enabled=true",
        "siem.postlogin.manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "siem.postlogin.operator-hold-file=/tmp/flare-postlogin-integration-hold.json",
        "siem.postlogin.publish-interval-ms=3600000", "siem.ueba.initial-delay-ms=3600000",
        "app.sensitive-action-confirmation.enabled=true",
        "app.sensitive-action-confirmation.account-allowlist=pl-integ-ready,pl-integ-cold,pl-integ-observe,pl-integ-db-fault"})
class PostloginGuardIntegrationTest extends ContainerizedIntegrationTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired EmailOtpService otp;
    @Autowired SensitiveActionConfirmationRepository actions;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.flarefitness.backend.service.siem.PostloginIncidentPublisher publisher;
    @Autowired com.flarefitness.backend.service.siem.PostloginDecisionService guard;
    @MockitoBean JavaMailSender mail;
    @MockitoBean com.flarefitness.backend.service.siem.SiemUebaGateway gateway;
    final Map<String,String> delivered=new ConcurrentHashMap<>();
    static final String CURRENT="CurrentPassword1!", REPLACEMENT="ReplacementPassword2!";
    final java.nio.file.Path holdFile=java.nio.file.Path.of("/tmp/flare-postlogin-integration-hold.json");

    void captureMail() {
        doAnswer(invocation -> {
            SimpleMailMessage message=invocation.getArgument(0);
            var matcher=Pattern.compile("\\b\\d{6}\\b").matcher(message.getText());
            assertThat(matcher.find()).isTrue();delivered.put(message.getTo()[0],matcher.group());return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }
    Map<String,Object> passwordRequest() {
        return Map.of("operation","PASSWORD_CHANGE","password",Map.of("current_password",CURRENT,
                "new_password",REPLACEMENT,"confirm_password",REPLACEMENT));
    }
    void configure(String mode) throws Exception {
        java.nio.file.Files.writeString(holdFile,"{\"hold_new_units\":false}");
        jdbc.update("UPDATE siem_postlogin_policy SET mode=?,account_allowlist_json=?,model_manifest_sha256=?,version=version+1 WHERE id=?",
                mode,"[\"pl-integ-ready\",\"pl-integ-cold\",\"pl-integ-observe\"]","a".repeat(64),"postlogin-project-limited-v1");
        org.mockito.Mockito.when(gateway.scorePostlogin(any(),any())).thenReturn(
                new com.flarefitness.backend.service.siem.SiemUebaGateway.PostloginScore(.99,100,"BEHAVIOR_REVIEW_CONTEXT",true,"b".repeat(64),"a".repeat(64)));
    }
    void trustedHistory(String user) {
        var at=LocalDateTime.now(ZoneOffset.UTC).withMinute(0).withSecond(0).withNano(0).minusHours(1);
        for(int i=0;i<30;i++) {
            jdbc.update("""
                INSERT INTO siem_account_behavior_windows
                (id,account_id,window_start,window_end,feature_schema_version,event_count,request_count,http_4xx_count,http_5xx_count,
                failed_login_count,successful_login_count,sensitive_action_count,distinct_route_group_count,distinct_source_ip_count,
                new_ip_flag,new_user_agent_flag,unusual_hour_flag,baseline_established,score_status,ngay_tao,updated_at,source_ip,user_agent_family)
                VALUES (?,?,?,?,1,10,10,0,0,0,0,0,1,1,false,false,false,false,'SCORED_RULE_ONLY',?,?,?,'OTHER')
                """,java.util.UUID.randomUUID().toString(),user,at.minusMinutes(i*15L),at.minusMinutes(i*15L).plusMinutes(15),at,at,"127.2.0.1");
        }
    }
    Map<String,Object> executeBody(String code,String request) { return Map.of("confirmation_code",code,"request_id",request); }
    int otpFailures(String user) { return jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_decisions WHERE user_id=? AND outcome='OTP_REJECTED'",Integer.class,user); }

    @Test @Timeout(180)
    void readyHoldIsPrewriteDurableIdempotentScopedAndL2Reviewed() throws Exception {
        captureMail();configure("ENFORCE_LIMITED");var user=fixture("pl-integ-ready");trustedHistory(user.getId());
        try(Client owner=new Client();Client another=new Client()) {
            login(owner,user);login(another,user);
            var challenge=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200));
            var stored=actions.findById(challenge.path("id").asText()).orElseThrow();
            assertThat(stored.getObservedAttemptId()).isNotBlank();
            String path="/api/profile/action-confirmations/"+stored.getId()+"/execute";
            String code=delivered.get(user.getEmail()),wrong=wrong(code),rid=java.util.UUID.randomUUID().toString();
            send(another,"POST",path,executeBody(code,java.util.UUID.randomUUID().toString()),409);
            send(owner,"POST",path,Map.of("confirmation_code",code),400);
            send(owner,"POST",path,executeBody(wrong,rid),400);
            send(owner,"POST",path,executeBody(wrong,rid),400);
            assertThat(otpFailures(user.getId())).isEqualTo(1);
            send(owner,"POST",path,executeBody(wrong,java.util.UUID.randomUUID().toString()),400);
            var denied=send(owner,"POST",path,executeBody(wrong,java.util.UUID.randomUUID().toString()),429);
            assertThat(body(denied).path("code").asText()).isEqualTo("ACTION_TEMPORARILY_HELD");
            assertThat(denied.headers().firstValue("Retry-After")).isPresent();
            String decision=body(denied).path("decision_id").asText();
            var expires=jdbc.queryForObject("SELECT expires_at FROM siem_postlogin_holds WHERE user_id=?",java.sql.Timestamp.class,user.getId());
            org.mockito.Mockito.when(gateway.scorePostlogin(any(),any())).thenThrow(new com.flarefitness.backend.exception.ServiceUnavailableException("test worker down"));
            send(owner,"POST",path,executeBody(code,java.util.UUID.randomUUID().toString()),429);
            assertThat(jdbc.queryForObject("SELECT expires_at FROM siem_postlogin_holds WHERE user_id=?",java.sql.Timestamp.class,user.getId())).isEqualTo(expires);
            assertThat(encoder.matches(CURRENT,users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
            publisher.publishPending();
            assertThat(jdbc.queryForObject("SELECT incident_id FROM siem_postlogin_decisions WHERE id=?",String.class,decision)).startsWith("postlogin-");
            User l1=soc("pl-l1","SOC_L1"),l2=soc("pl-l2","SOC_L2");
            try(Client first=new Client();Client second=new Client()) {
                login(first,l1);login(second,l2);
                var detail=body(send(first,"GET","/api/siem/postlogin-decisions/"+decision,null,200));
                long version=detail.path("summary").path("version").asLong();
                var release=Map.of("expected_version",version,"reason","Verified legitimate lab owner.");
                send(first,"POST","/api/siem/postlogin-decisions/"+decision+"/release",release,403);
                send(second,"POST","/api/siem/postlogin-decisions/"+decision+"/release",release,403);
                String incident=detail.path("summary").path("incident_id").asText();
                jdbc.update("UPDATE siem_incidents SET queue_tier='L2',status='IN_PROGRESS',assignee_user_id=?,version=version+1 WHERE id=?",l2.getId(),incident);
                send(second,"POST","/api/siem/postlogin-decisions/"+decision+"/release",release,200);
                send(second,"POST","/api/siem/postlogin-decisions/"+decision+"/release",release,409);
            }
            // Worker outage after an analyst release keeps OTP, and the actual password write remains atomic.
            send(owner,"POST",path,executeBody(code,java.util.UUID.randomUUID().toString()),200);
            assertThat(encoder.matches(REPLACEMENT,users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_decisions WHERE user_id=? AND outcome='COMMITTED'",Integer.class,user.getId())).isEqualTo(1);
        } finally { java.nio.file.Files.deleteIfExists(holdFile); }
    }
    User soc(String id,String role) {
        User u=new User();u.setId(id);u.setUsername(id);u.setPassword(encoder.encode(CURRENT));u.setRole(role);
        u.setHoTen("Guard integration analyst");u.setStatus("Hoat dong");u.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));return users.saveAndFlush(u);
    }

    @Test @Timeout(120)
    void coldNeverHoldsAndOperatorHoldChangesNewDecisionsToObserve() throws Exception {
        captureMail();configure("ENFORCE_LIMITED");var user=fixture("pl-integ-cold");
        try(Client owner=new Client()) {
            login(owner,user);
            var c=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200));
            String path="/api/profile/action-confirmations/"+c.path("id").asText()+"/execute",code=delivered.get(user.getEmail());
            for(int i=0;i<3;i++) send(owner,"POST",path,executeBody(wrong(code),java.util.UUID.randomUUID().toString()),400);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_holds WHERE user_id=? AND expires_at>UTC_TIMESTAMP(6)",Integer.class,user.getId())).isZero();
            java.nio.file.Files.writeString(holdFile,"{\"hold_new_units\":true}");
            send(owner,"POST",path,executeBody(code,java.util.UUID.randomUUID().toString()),200);
            assertThat(jdbc.queryForObject("SELECT mode FROM siem_postlogin_decisions WHERE user_id=? AND outcome='COMMITTED'",String.class,user.getId())).isEqualTo("OBSERVE");
        } finally { java.nio.file.Files.deleteIfExists(holdFile); }
    }

    @Test @Timeout(120)
    void observeNeverHoldsAndOnlyRealFreshSameSourceAbuseMayHoldInEnforce() throws Exception {
        captureMail();configure("OBSERVE");var user=fixture("pl-integ-observe");trustedHistory(user.getId());
        try(Client owner=new Client()) {
            login(owner,user);
            var c=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200));
            String path="/api/profile/action-confirmations/"+c.path("id").asText()+"/execute",code=delivered.get(user.getEmail());
            for(int i=0;i<3;i++) send(owner,"POST",path,executeBody(wrong(code),java.util.UUID.randomUUID().toString()),400);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM siem_postlogin_holds WHERE user_id=? AND expires_at>UTC_TIMESTAMP(6)",Integer.class,user.getId())).isZero();
            configure("ENFORCE_LIMITED"); // Old OBSERVE failures do not become an enforcement counter.
            var action=actions.findById(c.path("id").asText()).orElseThrow();
            var issued=jdbc.queryForObject("SELECT session_issued_at FROM siem_security_events WHERE id=?",LocalDateTime.class,action.getObservedAttemptId());
            var actor=new SensitiveActionConfirmationService.Actor(user.getUsername(),user.getId(),user.getAuthVersion()==null?0:user.getAuthVersion(),
                    new com.flarefitness.backend.service.siem.UebaSessionTelemetry(action.getSessionPseudonym(),issued));
            String source=owner.localAddress.getHostAddress(),other="127.99.99.99";
            seedScan(user.getId(),other);
            cacheAbuse(source,"REAL",true);
            assertProviderStepUp(actor,action,source);
            seedScan(user.getId(),source);
            cacheAbuse(source,"DEMO_ONLY",true);
            assertProviderStepUp(actor,action,source);
            // Start another policy epoch: the OTP-failure route must not mask intelligence gating.
            configure("ENFORCE_LIMITED");cacheAbuse(source,"REAL",false);
            assertProviderStepUp(actor,action,source);
            cacheAbuse(source,"REAL",true);
            send(owner,"POST",path,executeBody(wrong(code),java.util.UUID.randomUUID().toString()),429);
            assertThat(encoder.matches(CURRENT,users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
            jdbc.update("UPDATE siem_postlogin_holds SET expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE user_id=?",user.getId());
            cacheAbuse(source,"UNAVAILABLE",true);
            // Old pre-hold OTP failures cannot renew a hold without new corroboration.
            send(owner,"POST",path,executeBody(wrong(code),java.util.UUID.randomUUID().toString()),400);
        } finally { java.nio.file.Files.deleteIfExists(holdFile); }
    }
    void assertProviderStepUp(SensitiveActionConfirmationService.Actor actor,com.flarefitness.backend.entity.SensitiveActionConfirmation action,String source) {
        // Test the independent DB-backed decision gate without consuming the existing OTP retry budget.
        var ticket=guard.beforeExecute(actor,action.getId(),java.util.UUID.randomUUID().toString(),source);
        assertThat(jdbc.queryForObject("SELECT decision FROM siem_postlogin_decisions WHERE id=?",String.class,ticket.id())).isEqualTo("STEP_UP");
        guard.failed(ticket,actor,action.getOperation(),false);
    }
    @Test @Timeout(120)
    void failedDatabaseCommitKeepsCustomerUnchangedAndNeverCountsAsWrongOtp() throws Exception {
        captureMail();configure("ENFORCE_LIMITED");var user=fixture("pl-integ-db-fault");
        jdbc.update("UPDATE siem_postlogin_policy SET account_allowlist_json='[\"pl-integ-db-fault\"]',version=version+1");
        try(Client owner=new Client()) {
            login(owner,user);
            var c=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200));
            String path="/api/profile/action-confirmations/"+c.path("id").asText()+"/execute",rid=java.util.UUID.randomUUID().toString();
            jdbc.execute("ALTER TABLE sensitive_action_confirmations ADD CONSTRAINT pl_reject_commit CHECK (user_id<>'pl-integ-db-fault' OR state<>'COMMITTED')");
            try {
                var rejected=send(owner,"POST",path,executeBody(delivered.get(user.getEmail()),rid),400);
                assertThat(body(rejected).path("code").asText()).isEqualTo("DATA_CONSTRAINT_VIOLATION");
            }
            finally { jdbc.execute("ALTER TABLE sensitive_action_confirmations DROP CHECK pl_reject_commit"); }
            var unchanged=users.findById(user.getId()).orElseThrow();
            assertThat(unchanged.getPassword()).isEqualTo(user.getPassword());
            assertThat(unchanged.getAuthVersion()).isEqualTo(user.getAuthVersion());
            assertThat(otpFailures(user.getId())).isZero();
            assertThat(jdbc.queryForObject("SELECT outcome FROM siem_postlogin_decisions WHERE request_id=?",String.class,rid)).isEqualTo("BUSINESS_REJECTED");
        } finally { java.nio.file.Files.deleteIfExists(holdFile); }
    }
    void seedScan(String user,String ip) {
        var at=LocalDateTime.now(ZoneOffset.UTC).minusSeconds(5);
        var categories=com.flarefitness.backend.service.siem.EndpointCategory.values();
        for(int i=0;i<60;i++) jdbc.update("""
            INSERT INTO siem_security_events
            (id,event_timestamp,actor_user_id,source_ip,event_type,action,outcome,route_group,http_method,http_status,
            ngay_tao,telemetry_contract_version,session_pseudonym,session_issued_at,endpoint_category)
            VALUES (?,?,?,?,'HTTP_REQUEST','API_REQUEST','FAILURE','account','GET',404,?,3,?,?,?)
            """,java.util.UUID.randomUUID().toString(),at,user,ip,at,"f".repeat(64),at.minusMinutes(1),categories[i%7].name());
    }
    void cacheAbuse(String ip,String provenance,boolean fresh) {
        var at=LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
            INSERT INTO siem_ip_intelligence(id,ip_address,provider,status,abuse_score,total_reports,distinct_reporters,observed_at,expires_at,data_provenance)
            VALUES (?,?,'ABUSEIPDB','FRESH',90,5,3,?,?,?) ON DUPLICATE KEY UPDATE
            observed_at=VALUES(observed_at),expires_at=VALUES(expires_at),data_provenance=VALUES(data_provenance)
            """,java.util.UUID.randomUUID().toString(),ip,at.minusMinutes(1),fresh?at.plusMinutes(30):at.minusSeconds(1),provenance);
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
