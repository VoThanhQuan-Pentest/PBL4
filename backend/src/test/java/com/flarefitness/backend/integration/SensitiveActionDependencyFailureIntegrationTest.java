package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.SensitiveActionConfirmationService;
import com.flarefitness.backend.service.siem.SecurityEventService;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/** Real HTTP/DB/session/OTP plus narrowly injected dependency outages. */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, properties={
    "server.address=127.0.0.1","siem.enabled=false","siem.ueba.enabled=false","siem.prevention.enabled=false",
    "siem.security-events.enabled=false","management.health.mail.enabled=false","logging.level.AUDIT=OFF",
    "app.sensitive-action-confirmation.enabled=true",
    "app.sensitive-action-confirmation.account-allowlist=confirmation-password,confirmation-email,confirmation-mail-fault,confirmation-db-fault,confirmation-redis-fault,confirmation-attempt-lock,confirmation-worker-fault,confirmation-destination-binding,confirmation-lost-response"})
class SensitiveActionDependencyFailureIntegrationTest extends SensitiveActionConfirmationIntegrationTest {
    @MockitoSpyBean EmailOtpService scopedOtp;
    @MockitoSpyBean SensitiveActionConfirmationService actionExecution;
    @MockitoBean SecurityEventService events;

    @Test @Timeout(120)
    void truncatedRequestDoesNotExecuteAndLostCommitResponseCanBeReplayed() throws Exception {
        captureMail();var user=fixture("confirmation-lost-response");
        var committed=new java.util.concurrent.CountDownLatch(1);
        var release=new java.util.concurrent.CountDownLatch(1);
        var calls=new AtomicInteger();
        try(var owner=new Client()) {
            login(owner,user);
            String target="lost-response-destination@example.test";
            String id=body(send(owner,"POST","/api/profile/action-confirmations",Map.of("operation","EMAIL_CHANGE",
                    "profile",Map.of("ho_ten","Lab owner","email",target,"sdt","")),200)).path("id").asText();
            String code=delivered.get(user.getEmail());
            send(owner,"POST","/api/profile/email/otp",Map.of("email",target),200);
            var payload=Map.of("confirmation_code",code,"destination_otp_code",delivered.get(target));
            String path="/api/profile/action-confirmations/"+id+"/execute",csrf=csrf(owner);
            doAnswer(invocation->{
                calls.incrementAndGet();Object result=invocation.callRealMethod();committed.countDown();
                release.await(10,java.util.concurrent.TimeUnit.SECONDS);return result;
            }).when(actionExecution).execute(any(),anyString(),any());
            var store=((java.net.CookieManager)owner.http.cookieHandler().orElseThrow()).getCookieStore();
            String cookies=store.getCookies().stream().map(c->c.getName()+"="+c.getValue()).collect(java.util.stream.Collectors.joining("; "));
            // Authenticated, CSRF-valid request cut off in the JSON body before
            // controller execution. Credentials are never printed.
            try(var socket=new java.net.Socket()) {
                socket.bind(new java.net.InetSocketAddress(owner.localAddress,0));
                socket.connect(new java.net.InetSocketAddress("127.0.0.1",port));socket.setSoTimeout(3000);
                String request="POST "+path+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nCookie: "+cookies
                        +"\r\nX-XSRF-TOKEN: "+csrf+"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{";
                socket.getOutputStream().write(request.getBytes(java.nio.charset.StandardCharsets.UTF_8));socket.shutdownOutput();
                socket.getInputStream().readNBytes(1024);
            }
            assertThat(calls.get()).isZero();
            assertThat(users.findById(user.getId()).orElseThrow().getEmail()).isEqualTo(user.getEmail());
            assertThat(actions.findById(id).orElseThrow().getState()).isEqualTo("PENDING");
            var request=java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://127.0.0.1:"+port+path))
                    .timeout(java.time.Duration.ofSeconds(2)).header("Content-Type","application/json").header("X-XSRF-TOKEN",csrf(owner))
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(json.writeValueAsString(payload))).build();
            var response=owner.http.sendAsync(request,java.net.http.HttpResponse.BodyHandlers.ofString());
            try {
                assertThat(committed.await(5,java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                org.assertj.core.api.Assertions.assertThatThrownBy(()->response.get(5,java.util.concurrent.TimeUnit.SECONDS))
                        .hasCauseInstanceOf(java.net.http.HttpTimeoutException.class);
            } finally {release.countDown();}
            var once=actions.findById(id).orElseThrow();assertThat(once.getState()).isEqualTo("COMMITTED");
            assertThat(users.findById(user.getId()).orElseThrow().getEmail()).isEqualTo(target);
            send(owner,"POST",path,payload,200);
            assertThat(actions.findById(id).orElseThrow().getCompletedAt()).isEqualTo(once.getCompletedAt());
        } finally {release.countDown();}
    }

    @Test @Timeout(120)
    void proofForAnotherDestinationCannotChangeTheBoundEmail() throws Exception {
        captureMail();var user=fixture("confirmation-destination-binding");
        try(var owner=new Client()) {
            login(owner,user);
            String target="bound-destination-a@example.test", other="bound-destination-b@example.test";
            var profile=Map.of("ho_ten","Lab owner","email",target,"sdt","");
            String id=body(send(owner,"POST","/api/profile/action-confirmations",Map.of("operation","EMAIL_CHANGE","profile",profile),200)).path("id").asText();
            String currentCode=delivered.get(user.getEmail());
            send(owner,"POST","/api/profile/email/otp",Map.of("email",other),200);
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",
                    Map.of("confirmation_code",currentCode,"destination_otp_code",delivered.get(other)),400);
            assertThat(users.findById(user.getId()).orElseThrow().getEmail()).isEqualTo(user.getEmail());
            assertThat(actions.findById(id).orElseThrow().getState()).isEqualTo("PENDING");
            // Current-mail proof was consumed before the second proof failed;
            // database rollback cannot make the first proof reusable.
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",
                    Map.of("confirmation_code",currentCode,"destination_otp_code",delivered.get(other)),400);
            assertThat(users.findById(user.getId()).orElseThrow().getEmail()).isEqualTo(user.getEmail());
        }
    }

    @Test @Timeout(120)
    void unavailableProofStoreNeverCommitsAndAnUnconsumedProofCanRecover() throws Exception {
        captureMail(); var user=fixture("confirmation-redis-fault");
        try(var owner=new Client()) {
            login(owner,user);
            String id=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200)).path("id").asText();
            String code=delivered.get(user.getEmail());
            doThrow(new RedisConnectionFailureException("controlled proof-store outage")).doCallRealMethod()
                    .when(scopedOtp).verifySensitiveActionOtp(anyString(),anyString(),anyString(),anyString());
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",code),500);
            var unchanged=users.findById(user.getId()).orElseThrow();
            assertThat(unchanged.getPassword()).isEqualTo(user.getPassword());
            assertThat(unchanged.getAuthVersion()).isEqualTo(user.getAuthVersion());
            assertThat(actions.findById(id).orElseThrow().getState()).isEqualTo("PENDING");
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",code),200);
            assertThat(encoder.matches(REPLACEMENT,users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
        }
    }

    @Test @Timeout(120)
    void actualRedisFailureBudgetSurvivesPreparingANewOperation() throws Exception {
        var sends=new AtomicInteger();
        doAnswer(invocation->{
            SimpleMailMessage message=invocation.getArgument(0);
            var matcher=Pattern.compile("\\b\\d{6}\\b").matcher(message.getText());
            assertThat(matcher.find()).isTrue();delivered.put(message.getTo()[0],matcher.group());sends.incrementAndGet();return null;
        }).when(mail).send(any(SimpleMailMessage.class));
        var user=fixture("confirmation-attempt-lock");
        try(var owner=new Client()) {
            login(owner,user);
            String id=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200)).path("id").asText();
            String code=delivered.get(user.getEmail());
            for(int attempt=1;attempt<=5;attempt++)
                send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",wrong(code)),attempt==5?429:400);
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",code),429);
            send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),429);
            assertThat(sends.get()).isEqualTo(2); // Registration + original challenge only.
            assertThat(users.findById(user.getId()).orElseThrow().getPassword()).isEqualTo(user.getPassword());
        }
    }

    @Test @Timeout(120)
    void failedBehaviorTelemetryDoesNotBypassTheMandatoryProof() throws Exception {
        captureMail();var user=fixture("confirmation-worker-fault");
        when(events.isPostLoginEnabled()).thenReturn(true);
        doThrow(new IllegalStateException("controlled behavior dependency outage")).when(events).recordSensitiveActionAttempt(anyString(),anyString());
        try(var owner=new Client()) {
            login(owner,user);
            String id=body(send(owner,"POST","/api/profile/action-confirmations",passwordRequest(),200)).path("id").asText();
            String code=delivered.get(user.getEmail());
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",wrong(code)),400);
            assertThat(users.findById(user.getId()).orElseThrow().getPassword()).isEqualTo(user.getPassword());
            send(owner,"POST","/api/profile/action-confirmations/"+id+"/execute",Map.of("confirmation_code",code),200);
            assertThat(encoder.matches(REPLACEMENT,users.findById(user.getId()).orElseThrow().getPassword())).isTrue();
        }
    }
}
