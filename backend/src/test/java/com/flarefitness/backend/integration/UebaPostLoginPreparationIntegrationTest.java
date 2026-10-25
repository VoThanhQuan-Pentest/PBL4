package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.clearInvocations;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.ops.PostLoginFeatureExport;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.service.siem.*;
import com.flarefitness.backend.controller.OwnedLabControlledFaultController;
import java.net.*;
import java.net.http.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/** Real clock, real HTTP/JWT/CSRF/OTP, isolated persistent DB; never packaged in the app. */
@EnabledIfSystemProperty(named="postlogin.preparation.enabled", matches="true")
@ActiveProfiles("ueba-operator")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, properties={
    "server.address=127.0.0.1", "siem.enabled=false", "siem.ueba.enabled=true", "siem.prevention.enabled=false",
    "siem.security-events.enabled=true", "siem.security-events.post-login-enabled=true",
    "management.health.mail.enabled=false", "logging.level.AUDIT=OFF",
    "app.sensitive-action-confirmation.enabled=true"})
@Import(OwnedLabControlledFaultController.class)
class UebaPostLoginPreparationIntegrationTest {
    static final int BANK=144, ACCOUNTS=432;
    static final Path ROOT=Path.of(System.getProperty("postlogin.preparation.output", "/nonexistent-preparation-output")).toAbsolutePath();
    static final String RUN=sha(ROOT.toString()).substring(0,8);
    static String account(int i) { return "plp-"+RUN+"-"+i; }
    static String setting(String key) {
        String v=System.getenv(key); if(v==null||v.isBlank()) throw new IllegalStateException("Dedicated lab configuration missing: "+key); return v;
    }
    @DynamicPropertySource static void configuration(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url",()->setting("FLARE_PREPARATION_DB_URL"));
        r.add("spring.datasource.username",()->"flare"); r.add("spring.datasource.password",()->"flare-preparation-only");
        r.add("spring.data.redis.host",()->"127.0.0.1");
        r.add("spring.data.redis.port",()->setting("FLARE_PREPARATION_REDIS_PORT"));
        r.add("spring.data.redis.password",()->"flare-preparation-redis-only");
        r.add("app.jwt.secret",()->"isolated-preparation-only-jwt-secret-never-a-production-key");
        r.add("app.security.auth-cookie-secure",()->"false");
        r.add("app.mail.from",()->"lab@example.test"); r.add("spring.mail.username",()->"lab@example.test");
        r.add("spring.mail.password",()->"not-a-real-mail-credential");
        r.add("app.sensitive-action-confirmation.account-allowlist",()->IntStream.range(0,ACCOUNTS).mapToObj(UebaPostLoginPreparationIntegrationTest::account).collect(java.util.stream.Collectors.joining(",")));
    }
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired SiemSecurityEventRepository events;
    @Autowired SiemAccountBehaviorWindowRepository windows;
    @Autowired SiemUebaModelJobRepository jobs;
    @Autowired AccountBehaviorAggregationWorker aggregation;
    @MockitoBean JavaMailSender mail;
    @MockitoBean SecurityEventExportWorker externalSink;
    @MockitoSpyBean SecurityEventService observed;
    final Map<String,String> delivered=new ConcurrentHashMap<>();
    final HttpClient[] transports=new HttpClient[32];
    final Map<Integer,Client> clients=new HashMap<>();
    final Map<String,Deque<Long>> loginTimes=new HashMap<>();
    final AtomicInteger attempts=new AtomicInteger();
    String password; String passwordHash; Plan armed; long jobsBefore; long lastSizeCheck;
    record Plan(String id,int account,String operation,String family,int contextClass,String role,boolean validProof,String cohort) { }

    @Test @Timeout(56800)
    void preparesRealTimeSourceWithoutFittingOrSendingExternalMail() throws Exception {
        if(!Files.isDirectory(ROOT)||Files.isSymbolicLink(ROOT)) throw new IllegalStateException("Owned preparation root required");
        Path secrets=ROOT.resolve("lab-client-secret.private.txt");
        if(Files.exists(secrets)) password=Files.readString(secrets);
        else { password="Preparation#"+UUID.randomUUID(); Files.writeString(secrets,password,StandardOpenOption.CREATE_NEW); Files.setPosixFilePermissions(secrets,PosixFilePermissions.fromString("rw-------")); }
        passwordHash=encoder.encode(password); jobsBefore=jobs.count();
        Path counter=ROOT.getParent().resolve("preparation-sensitive-count.private.json");
        if(Files.exists(counter)) attempts.set(json.readTree(Files.readString(counter)).path("sensitive_attempts").asInt());
        doAnswer(call->{var m=(SimpleMailMessage)call.getArgument(0);var match=Pattern.compile("\\b\\d{6}\\b").matcher(m.getText());assertThat(match.find()).isTrue();delivered.put(m.getTo()[0],match.group());return null;}).when(mail).send(any(SimpleMailMessage.class));
        doAnswer(call->{call.callRealMethod();int n=attempts.incrementAndGet();assertThat(n).isLessThanOrEqualTo(1000);publish(counter,Map.of("sensitive_attempts",n,"updated_at",Instant.now().toString()));if(armed!=null&&account(armed.account()).equals(call.getArgument(1))) capture(armed);return null;}).when(observed).recordSensitiveActionAttempt(anyString(),anyString());
        String mode=System.getProperty("postlogin.preparation.mode","smoke");
        boolean full="collect".equals(mode);
        if(mode.equals("recovery-check")){
            for(int pair=0;pair<3;pair++)for(int role=0;role<2;role++){
                Path receipt=ROOT.resolve("p1-"+pair+"-"+role+"-outcome.receipt.private.json");
                boolean changed=json.readTree(Files.readString(receipt)).path("account_mutated").asBoolean();
                User u=users.findById(account(pair*2+role)).orElseThrow();
                assertThat(encoder.matches(changed?"PreparationNext#Password2!":password,u.getPassword())).isTrue();
            }
            commit("persistent-db-restart-check-v1",Map.of("status","ACTUAL_DATABASE_RESTART_READBACK_PASS","new_fits",0,"new_sensitive_attempts",0,"persisted_accounts",6));
            progress("RECOVERY_CHECK_PASS_0_FIT",0);return;
        }
        progress("STARTING",0);
        try {
            if(full) {
                // After warmup, retain exactly the closed history used by the
                // completed benchmark cases; do not aggregate benchmark traffic.
                if(!Files.exists(ROOT.resolve("warmup-window-47.commit.private.json"))) reconcileClosedHistory();
                warmup();
            }
            int pairs=full?12:3;
            for(int pair=full?3:0;pair<pairs;pair++) for(int role=0;role<2;role++) {
                int kind=pair%6;String family=switch(kind){case 3->"request_burst";case 4->"auth_failure_burst";case 5->"http_error_burst";default->"normal";};
                boolean valid=kind==2||kind!=1&&role==0;
                execute(new Plan("p1-"+pair+"-"+role,pair*2+role,pair<6?"PASSWORD_CHANGE":"EMAIL_CHANGE",family,kind>=3?(kind==5?2:1):0,role==0?"OWNER":"NONOWNER",valid,full?"READY":"COLD"));
            }
            if(full) {
                String[] families={"normal","request_burst","endpoint_scan","auth_failure_burst","sensitive_action_burst","http_error_burst"};
                for(int cohort=0;cohort<3;cohort++) for(int f=0;f<6;f++) for(int i=0;i<20;i++) {
                    int ordinal=cohort*BANK+(cohort==0?24:0)+f*20+i;
                    execute(new Plan("benchmark-"+cohort+"-"+f+"-"+i,ordinal,i%2==0?"PASSWORD_CHANGE":"EMAIL_CHANGE",families[f],f==0?0:f==5?2:1,i%2==0?"OWNER":"NONOWNER",i%4!=1,new String[]{"READY","UNSEEN_READY","COLD"}[cohort]));
                }
            }
            assertThat(jobs.count()).isEqualTo(jobsBefore);
            commit("preparation-capture-result-v1",Map.of("status",full?"REAL_TIME_PREPARATION_CAPTURE_COMPLETE":"COLD_READINESS_SMOKE_ONLY","new_fits",0,"new_model_jobs",jobs.count()-jobsBefore,"external_mail",false,"sensitive_attempts",attempts.get(),"p1_target_episodes",full?18:pairs*2,"benchmark_target_episodes",full?360:0,"source_class","CONTROLLED_REAL_TIME_LAB","holdout_scored",false,"auto_containment",false));
            progress(full?"CAPTURE_COMPLETE_0_FIT":"SMOKE_COMPLETE_0_FIT",full?48:0);
        } finally { for(var h:transports) if(h!=null) h.close(); }
    }

    void reconcileClosedHistory() throws Exception {
        // Recover observed closed frames left between the last durable wave and
        // a safe stop. No events or windows are fabricated for the offline gap.
        resourceGuard();
        for(int pass=0;pass<16;pass++) aggregation.aggregatePending();
        LocalDateTime cutoff=window(LocalDateTime.now(ZoneOffset.UTC));
        var recovered=new TreeMap<LocalDateTime,List<Map<String,Object>>>();
        for(int i=0;i<ACCOUNTS;i++) {
            resourceGuard();
            for(var w:windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(account(i),cutoff.minusDays(14),cutoff)) {
                if(w.getWindowEnd().isAfter(cutoff)) continue;
                var raw=events.findAccountEvidence(account(i),w.getWindowStart(),w.getWindowEnd(),PageRequest.of(0,10000)).getContent();
                assertThat(raw).isNotEmpty();
                recovered.computeIfAbsent(w.getWindowStart(),key->new ArrayList<>()).add(Map.of(
                    "account_id",account(i),"window_id_sha256",sha(w.getId()),
                    "window_start",w.getWindowStart().toInstant(ZoneOffset.UTC).toString(),
                    "window_end",w.getWindowEnd().toInstant(ZoneOffset.UTC).toString(),
                    "features",w.modelFeatureVector(4),"events",raw.stream().map(this::sanitized).toList()));
            }
        }
        for(var entry:recovered.entrySet()) {
            String phase="resume-history-"+entry.getKey().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            commit(phase,Map.of("status","OBSERVED_CLOSED_HISTORY_RECONCILED","real_clock",true,
                "window_start",entry.getKey().toString(),"rows",entry.getValue()));
        }
    }

    void warmup() throws Exception {
        int done=0;while(Files.exists(ROOT.resolve("warmup-window-"+done+".commit.private.json"))) done++;
        while(done<48) {
            resourceGuard(); LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
            LocalDateTime start=window(now);
            if(Duration.between(now,start.plusMinutes(15)).toSeconds()<300){
                while(LocalDateTime.now(ZoneOffset.UTC).isBefore(start.plusMinutes(15).plusSeconds(1))){resourceGuard();progress("WAIT_FULL_REAL_WINDOW",done);Thread.sleep(15000);}
                start=window(LocalDateTime.now(ZoneOffset.UTC));
            }
            int count=done>=45?ACCOUNTS:BANK*2;
            for(int i=0;i<count;i++) { Client c=client(i);send(c,"GET","/api/profile",null); }
            LocalDateTime end=start.plusMinutes(15);
            while(LocalDateTime.now(ZoneOffset.UTC).isBefore(end.plusSeconds(122))) { resourceGuard();progress("WAIT_REAL_WINDOW_CLOSE",done);Thread.sleep(15000); }
            for(int pass=0;pass<16;pass++) aggregation.aggregatePending();
            var evidence=new ArrayList<Map<String,Object>>();
            for(int i=0;i<count;i++) {
                var w=windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(account(i),start,1).orElseThrow();
                var raw=events.findAccountEvidence(account(i),start,end,PageRequest.of(0,10000)).getContent();
                evidence.add(Map.of("account_id",account(i),"window_start",start.toInstant(ZoneOffset.UTC).toString(),"window_end",end.toInstant(ZoneOffset.UTC).toString(),"features",w.modelFeatureVector(4),"events",raw.stream().map(this::sanitized).toList()));
            }
            commit("warmup-window-"+done,Map.of("status","REAL_CLOSED_HISTORY_COMMITTED","real_clock",true,"window_start",start.toString(),"rows",evidence));
            progress("WARMUP",++done);clearInvocations(observed,mail);
        }
    }

    void execute(Plan p) throws Exception {
        if(Files.exists(ROOT.resolve(p.id()+"-outcome.commit.private.json"))) return;
        if(Files.exists(ROOT.resolve(p.id()+"-precommit.commit.private.json"))) throw new IllegalStateException("CENSORED_PARTIAL_CASE_REQUIRES_RECONCILIATION");
        resourceGuard();long begin=System.nanoTime();
        Path previousOracle=ROOT.resolve(p.id()+"-oracle.receipt.private.json");
        if(Files.exists(previousOracle)) {
            var oracle=json.readTree(Files.readString(previousOracle));
            assertThat(oracle.path("case_id").asText()).isEqualTo(p.id());
            assertThat(oracle.path("context_class").asInt()).isEqualTo(p.contextClass());
            assertThat(oracle.path("family").asText()).isEqualTo(p.family());
            assertThat(oracle.path("actor_role").asText()).isEqualTo(p.role());
            assertThat(oracle.path("operation").asText()).isEqualTo(p.operation());
            assertThat(oracle.path("valid_proof_planned").asBoolean()).isEqualTo(p.validProof());
            Path recovery=ROOT.getParent().resolve("partial-case-reconciliation-v1.receipt.private.json");
            var marker=json.readTree(Files.readString(ROOT.getParent().resolve("partial-case-reconciliation-v1.commit.private.json")));
            assertThat(marker.path("receipt_sha256").asText()).isEqualTo(fileHash(recovery));
            var proof=json.readTree(Files.readString(recovery));
            assertThat(proof.path("status").asText()).isEqualTo("VERIFIED_NO_TARGET_ATTEMPT_BEFORE_OOM");
            assertThat(proof.path("case_id").asText()).isEqualTo(p.id());
            assertThat(proof.path("oracle_sha256").asText()).isEqualTo(fileHash(previousOracle));
            assertThat(proof.path("target_sensitive_attempts_after_oracle").asInt(-1)).isZero();
            Instant cooldown=Instant.parse(proof.path("context_cooldown_until").asText());
            while(Instant.now().isBefore(cooldown)) { resourceGuard();Thread.sleep(15000); }
            // Include the failed context work and recovery wait in measured cost.
            begin-=Duration.between(Instant.parse(oracle.path("sealed_at").asText()),Instant.now()).toNanos();
        }
        commit(p.id()+"-oracle",Map.of("case_id",p.id(),"context_class",p.contextClass(),"family",p.family(),"actor_role",p.role(),"operation",p.operation(),"valid_proof_planned",p.validProof(),"sealed_at",Instant.now().toString(),"label_basis","PRESEALED_SCENARIO_NOT_FEATURE_THRESHOLDS"));
        Client c=client(p.account());
        if(p.role().equals("NONOWNER")){Client actor=new Client(c.ordinal,c.http);for(var cookie:c.cookies.getCookieStore().getCookies())actor.cookies.getCookieStore().add(URI.create("http://127.0.0.1:"+port),cookie);c=actor;}
        if(p.family().equals("request_burst")) for(int i=0;i<150;i++) send(c,"GET","/api/profile",null);
        if(p.family().equals("http_error_burst")) for(int i=0;i<50;i++) assertThat(send(c,"GET","/api/owned-lab/controlled-faults",null).statusCode()).isEqualTo(503);
        if(p.family().equals("auth_failure_burst")) {for(int i=0;i<8;i++) send(c,"POST","/api/auth/login",Map.of("username",account(p.account()),"password","WrongPreparationPassword#"));login(c);}
        if(p.family().equals("sensitive_action_burst")) for(int i=0;i<5;i++) send(c,"PUT","/api/profile/password",Map.of("current_password",password,"new_password","Temporary#Replacement2!","confirm_password","Temporary#Replacement2!"));
        if(p.family().equals("endpoint_scan")) {
            String[] routes={"/api/products/nonexistent-lab-product","/api/orders/nonexistent-lab-order/cancel-request","/api/orders/nonexistent-lab-order/return-request","/api/reviews","/api/profile/email/otp","/api/profile/password","/api/profile","/api/nonexistent-lab-route"};
            String[] methods={"GET","POST","POST","POST","POST","PUT","PUT","GET"};
            for(int i=0;i<60;i++){int j=i%8;send(c,methods[j],routes[j],methods[j].equals("GET")?null:Map.of());}
        }
        User before=users.findById(account(p.account())).orElseThrow();
        String target=account(p.account())+"-destination@example.test";
        Object payload=p.operation().equals("PASSWORD_CHANGE")?Map.of("operation",p.operation(),"password",Map.of("current_password",password,"new_password","PreparationNext#Password2!","confirm_password","PreparationNext#Password2!")):Map.of("operation",p.operation(),"profile",Map.of("ho_ten","Lab owner","email",target,"sdt",""));
        armed=p;HttpResponse<String> prepared;
        try {prepared=send(c,"POST","/api/profile/action-confirmations",payload);} finally {armed=null;}
        assertThat(prepared.statusCode()).as("prepare "+p.id()).isEqualTo(200);
        assertThat(Files.exists(ROOT.resolve(p.id()+"-precommit.commit.private.json"))).isTrue();
        String challenge=json.readTree(prepared.body()).path("id").asText();String code=delivered.remove(before.getEmail());String destination="";
        if(p.operation().equals("EMAIL_CHANGE")){assertThat(send(c,"POST","/api/profile/email/otp",Map.of("email",target)).statusCode()).isEqualTo(200);destination=delivered.remove(target);}
        if(!p.validProof()) code="";
        var result=send(c,"POST","/api/profile/action-confirmations/"+challenge+"/execute",Map.of("confirmation_code",code,"destination_otp_code",destination));
        assertThat(result.statusCode()).as("execute "+p.id()).isEqualTo(p.validProof()?200:400);
        var after=users.findById(before.getId()).orElseThrow();
        boolean changed=p.operation().equals("PASSWORD_CHANGE")?!before.getPassword().equals(after.getPassword()):!before.getEmail().equals(after.getEmail());
        assertThat(changed).isEqualTo(p.validProof());
        commit(p.id()+"-outcome",Map.of("case_id",p.id(),"actor_role",p.role(),"http_status",result.statusCode(),"account_mutated",changed,"valid_proof",p.validProof(),"elapsed_seconds",(System.nanoTime()-begin)/1e9,"shared_mailbox_limit",p.role().equals("NONOWNER")&&p.validProof()));
        progress("CAPTURE",48);clearInvocations(observed,mail);
    }

    void capture(Plan p) throws Exception {
        LocalDateTime at=LocalDateTime.now(ZoneOffset.UTC);
        var context=events.findAccountEvidence(account(p.account()),at.minusMinutes(15).minusSeconds(1),at.plusSeconds(1),PageRequest.of(0,10000)).getContent();
        var attempt=context.stream().filter(e->"SENSITIVE_ACTION_ATTEMPT".equals(e.getEventType())).max(Comparator.comparing(SiemSecurityEvent::getEventTimestamp)).orElseThrow();
        LocalDateTime start=window(attempt.getEventTimestamp());
        var history=windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(account(p.account()),start.minusDays(14),start).stream().filter(w->!w.getWindowEnd().isAfter(start)).toList();
        var typed=PostLoginFeatureExport.fromObservedRisk(attempt,context,history);
        if(System.getProperty("postlogin.preparation.mode","smoke").equals("collect")) {
            assertThat(typed.observed().baselineEstablished()).isEqualTo(!p.cohort().equals("COLD"));
            if(p.cohort().equals("COLD"))assertThat(typed.observed().trustedWindowCount()).isBetween(1,29);
            else assertThat(typed.observed().trustedWindowCount()).isGreaterThanOrEqualTo(48);
        }
        var names=new ArrayList<>(AccountBehaviorFeatures.names(4));names.addAll(typed.observed().postlogin().names());names.addAll(PostLoginRiskContextFeatures.NAMES);
        Map<String,Object> snapshot=Map.of("snapshot_id","capture-"+p.id(),"evaluation_unit","SENSITIVE_ACTION_ATTEMPT","feature_schema_version",6,"feature_names",names,"features",typed.values(),"as_of",attempt.getEventTimestamp().toInstant(ZoneOffset.UTC).toString(),"baseline_established",typed.observed().baselineEstablished(),"trusted_window_count",typed.observed().trustedWindowCount());
        commit(p.id()+"-precommit",Map.of("case_id",p.id(),"snapshot",snapshot,"current_outcome_known",false,"account_mutation_observed_at_capture",false,"oracle_sha256",fileHash(ROOT.resolve(p.id()+"-oracle.receipt.private.json")),"attempt",sanitized(attempt),"context",context.stream().filter(e->e.getEventTimestamp().isBefore(attempt.getEventTimestamp())).map(this::sanitized).toList(),"history_window_ids",history.stream().map(w->sha(w.getId())).toList()));
    }

    Client client(int i) throws Exception {
        if(clients.containsKey(i)) return clients.get(i);
        if(users.findById(account(i)).isEmpty()) {
            User u=new User();u.setId(account(i));u.setUsername(account(i));u.setEmail(account(i)+"@example.test");u.setEmailVerifiedAt(LocalDateTime.now(ZoneOffset.UTC));u.setAuthVersion(0L);u.setPassword(passwordHash);u.setRole("CUSTOMER");u.setHoTen("Lab owner");u.setStatus("Hoat dong");u.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));users.saveAndFlush(u);
        }
        int slot=i%32;if(transports[slot]==null)transports[slot]=HttpClient.newBuilder().localAddress(InetAddress.getByName("127.14.0."+(slot+2))).connectTimeout(Duration.ofSeconds(10)).build();
        Client c=new Client(i,transports[slot]);clients.put(i,c);login(c);return c;
    }
    void login(Client c) throws Exception {assertThat(send(c,"POST","/api/auth/login",Map.of("username",account(c.ordinal),"password",password)).statusCode()).isEqualTo(200);}
    class Client {final int ordinal;final HttpClient http;final CookieManager cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);Client(int i,HttpClient h){ordinal=i;http=h;}}
    HttpResponse<String> send(Client c,String method,String path,Object body) throws Exception {
        resourceGuard();if((path.equals("/api/profile/action-confirmations")||path.equals("/api/profile/password"))&&attempts.get()>=1000)throw new IllegalStateException("SENSITIVE_ATTEMPT_CAP");
        if(path.equals("/api/auth/login")) paceLogin(c);
        String csrf=null;if(body!=null){var r=send(c,"GET","/api/auth/csrf",null);assertThat(r.statusCode()).isEqualTo(200);csrf=json.readTree(r.body()).path("token").asText();}
        URI uri=URI.create("http://127.0.0.1:"+port+path);var b=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).header("User-Agent","FlareLocalLab/1.0");
        c.cookies.get(uri,Map.of()).forEach((key,values)->values.forEach(v->b.header(key,v)));
        if(csrf!=null)b.header("X-XSRF-TOKEN",csrf);
        if(body==null)b.method(method,HttpRequest.BodyPublishers.noBody());else b.header("Content-Type","application/json").method(method,HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        var response=c.http.send(b.build(),HttpResponse.BodyHandlers.ofString());c.cookies.put(uri,response.headers().map());return response;
    }
    void paceLogin(Client c)throws Exception {
        // The application defaults to5 attempts/minute perIP and account. Keep
        // a spare slot, retain real timing, and never weaken Redis throttles.
        String[] keys={"ip-"+(c.ordinal%32),"account-"+c.ordinal};
        while(true){
            long now=System.currentTimeMillis(),wait=0;
            for(String key:keys){var q=loginTimes.computeIfAbsent(key,k->new ArrayDeque<>());while(!q.isEmpty()&&q.peekFirst()<=now-61000)q.removeFirst();if(q.size()>=4)wait=Math.max(wait,q.peekFirst()+61001-now);}
            if(wait==0){for(String key:keys)loginTimes.get(key).addLast(now);return;}
            resourceGuard();Thread.sleep(Math.min(wait,15000));
        }
    }
    void resourceGuard() throws Exception {
        if(System.nanoTime()-lastSizeCheck>Duration.ofMinutes(1).toNanos()){
            try(var paths=Files.walk(ROOT)){long bytes=paths.filter(Files::isRegularFile).mapToLong(p->{try{return Files.size(p);}catch(Exception e){throw new IllegalStateException(e);}}).sum();if(bytes>=2L*1024*1024*1024)throw new IllegalStateException("OUTPUT_BYTE_CAP");}
            lastSizeCheck=System.nanoTime();
        }
        if(Files.getFileStore(ROOT).getUsableSpace()<5_000_000_000L)throw new IllegalStateException("DISK_RESERVE");
        if(Files.exists(ROOT.resolve("operator-hold.private.json"))&&json.readTree(Files.readString(ROOT.resolve("operator-hold.private.json"))).path("hold_new_units").asBoolean())throw new IllegalStateException("OPERATOR_HOLD");
    }
    void progress(String phase,int count) throws Exception {publish(ROOT.resolve("preparation-progress.private.json"),Map.of("phase",phase,"closed_warmup_windows",count,"sensitive_attempts",attempts.get(),"new_fits",0,"quota_policy","NOT_USED","updated_at",Instant.now().toString()));}
    Map<String,Object> sanitized(SiemSecurityEvent e) {
        var m=new LinkedHashMap<String,Object>();m.put("event_id",sha(e.getId()));
        for(var entry:Map.of("event_type",Objects.toString(e.getEventType(),""),"action",Objects.toString(e.getAction(),""),"outcome",Objects.toString(e.getOutcome(),"")).entrySet())m.put(entry.getKey(),entry.getValue());
        if(e.getActorUserId()!=null)m.put("actor_user_id",e.getActorUserId());if(e.getTargetUserId()!=null)m.put("target_user_id",e.getTargetUserId());
        m.put("event_timestamp",e.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());m.put("telemetry_contract_version",e.getTelemetryContractVersion());
        if(e.getSessionPseudonym()!=null)m.put("session_pseudonym",e.getSessionPseudonym());if(e.getSessionIssuedAt()!=null)m.put("session_issued_at",e.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
        if(e.getHttpStatus()!=null)m.put("http_status",e.getHttpStatus());if(e.getEndpointCategory()!=null)m.put("endpoint_category",e.getEndpointCategory());
        if(e.getHttpMethod()!=null)m.put("http_method",e.getHttpMethod());if(e.getRouteGroup()!=null)m.put("route_group",e.getRouteGroup());
        if(e.getSourceIp()!=null)m.put("source_ip",e.getSourceIp());if(e.getUserAgentFamily()!=null)m.put("user_agent_family",e.getUserAgentFamily());return m;
    }
    static LocalDateTime window(LocalDateTime t){return t.withMinute(t.getMinute()/15*15).withSecond(0).withNano(0);}
    static String sha(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    static String fileHash(Path p)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
    void commit(String phase,Object value)throws Exception{
        Path receipt=ROOT.resolve(phase+".receipt.private.json"),marker=ROOT.resolve(phase+".commit.private.json");
        if(Files.exists(marker)){assertThat(json.readTree(Files.readString(marker)).path("receipt_sha256").asText()).isEqualTo(fileHash(receipt));return;}
        publish(receipt,value);publish(marker,Map.of("phase",phase,"receipt",receipt.getFileName().toString(),"receipt_sha256",fileHash(receipt)));
    }
    void publish(Path target,Object value)throws Exception{
        byte[] data=json.writeValueAsBytes(value);if(data.length>4*1024*1024)throw new IllegalArgumentException("Bounded capture artifact required");
        Path temp=Files.createTempFile(target.getParent(),".capture-pending-",".json",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try(FileChannel out=FileChannel.open(temp,StandardOpenOption.WRITE)){ByteBuffer b=ByteBuffer.wrap(data);while(b.hasRemaining())out.write(b);out.force(true);}
        Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);try(FileChannel d=FileChannel.open(target.getParent(),StandardOpenOption.READ)){d.force(true);}
    }
}
