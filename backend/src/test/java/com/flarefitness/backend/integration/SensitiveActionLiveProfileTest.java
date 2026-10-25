package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.EmailOtpService;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Real SMTP + human input + actual HTTP/JWT/CSRF/MySQL/Redis; disposable account only. */
@EnabledIfEnvironmentVariable(named="FLARE_LIVE_PROFILE_SMOKE",matches="true")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "server.address=127.0.0.1","siem.enabled=false","siem.ueba.enabled=false","siem.prevention.enabled=false",
    "siem.security-events.enabled=false","management.health.mail.enabled=false","logging.level.AUDIT=OFF",
    "app.sensitive-action-confirmation.enabled=true","app.sensitive-action-confirmation.account-allowlist=live-mail-owner"})
class SensitiveActionLiveProfileTest extends ContainerizedIntegrationTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired EmailOtpService otp;
    @Autowired IpRateLimitService limits;
    @Autowired PasswordEncoder encoder;
    static final String OLD="LiveLabPassword1!", NEXT="LiveLabPassword2!";
    String emailId, passwordId, csrf;
    @Test @Timeout(1170)
    void humanProvesBothMutationsBeforeDatabaseCommit() throws Exception {
        String recipient=System.getenv("FLARE_LIVE_MAIL_RECIPIENT");
        assertThat(recipient.endsWith("@gmail.com") && !recipient.contains("+")).isTrue();
        String target=recipient.replace("@gmail.com","+flare-live-lab@gmail.com");
        Path output=Path.of(System.getenv("FLARE_LIVE_MAIL_OUTPUT"));
        String base="/lab/profile-proof/"+UUID.randomUUID().toString().replace("-","");
        var stage=new AtomicInteger();var mailAttempts=new AtomicInteger();var done=new CountDownLatch(1);
        var cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);
        long started=System.nanoTime();
        try(var client=HttpClient.newBuilder().cookieHandler(cookies).build()) {
            var server=HttpServer.create(new InetSocketAddress("127.0.0.1",58069),0);
            server.createContext(base,exchange->{
                int status=200;String message="";byte[] response;
                try {
                    String path=exchange.getRequestURI().getPath();
                    if(!"localhost:58069".equals(exchange.getRequestHeaders().getFirst("Host")))throw new IllegalArgumentException();
                    if(exchange.getRequestMethod().equals("GET") && path.equals(base)) {
                        exchange.getResponseHeaders().set("Content-Type","text/html; charset=utf-8");
                        response=page().getBytes(StandardCharsets.UTF_8);
                    } else {
                        if(!exchange.getRequestMethod().equals("POST") || !"http://localhost:58069".equals(exchange.getRequestHeaders().getFirst("Origin"))
                            || !"application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type")))throw new IllegalArgumentException();
                        byte[] body=exchange.getRequestBody().readNBytes(513);if(body.length>512)throw new IllegalArgumentException();
                        var input=json.readTree(body);String step=path.substring(base.length());
                        if(step.equals("/contact/send") && stage.compareAndSet(0,1)) {
                            limits.assertOtpSendAllowed(EmailOtpService.PURPOSE_REGISTER,recipient,"127.0.0.1");mailAttempts.incrementAndGet();
                            otp.sendOtp(EmailOtpService.PURPOSE_REGISTER,recipient);message="Đã gửi mã xác minh mailbox lab. Nhập ở bước 1.";
                        } else if(step.equals("/contact/verify") && stage.get()==1) {
                            otp.verifyOtp(EmailOtpService.PURPOSE_REGISTER,recipient,input.path("code").asText());
                            User user=new User();user.setId("live-mail-owner");user.setUsername("live-mail-owner");user.setRole("CUSTOMER");
                            user.setHoTen("Live lab owner");user.setEmail(recipient);user.setEmailVerifiedAt(LocalDateTime.now(ZoneOffset.UTC));
                            user.setPassword(encoder.encode(OLD));user.setAuthVersion(0L);user.setStatus("Hoat dong");user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));users.saveAndFlush(user);
                            call(client,"POST","/api/auth/login",Map.of("username",user.getUsername(),"password",OLD),200);stage.set(2);
                            message="Đã xác minh mailbox và đăng nhập tài khoản lab. Tiếp tục bước 2.";
                        } else if(step.equals("/email/prepare") && stage.compareAndSet(2,3)) {
                            var profile=Map.of("ho_ten","Live lab owner","email",target,"sdt","0900000019");mailAttempts.incrementAndGet();
                            var prepared=call(client,"POST","/api/profile/action-confirmations",Map.of("operation","EMAIL_CHANGE","profile",profile),200);
                            emailId=prepared.path("id").asText();mailAttempts.incrementAndGet();
                            call(client,"POST","/api/profile/email/otp",Map.of("email",target),200);
                            assertThat(users.findById("live-mail-owner").orElseThrow().getEmail().equals(recipient)).isTrue();
                            message="Đã gửi 2 email: mã xác nhận đổi email gửi tới địa chỉ cũ; mã OTP email mới gửi tới alias +flare-live-lab. Nhập đúng hai ô bước 2.";
                        } else if(step.equals("/email/execute") && stage.get()==3) {
                            call(client,"POST","/api/profile/action-confirmations/"+emailId+"/execute",Map.of("confirmation_code",input.path("code").asText(),"destination_otp_code",input.path("destination").asText()),200);
                            assertThat(users.findById("live-mail-owner").orElseThrow().getEmail().equals(target)).isTrue();stage.set(4);
                            message="Đổi email của tài khoản lab đã commit sau hai bằng chứng hợp lệ. Tiếp tục bước 3.";
                        } else if(step.equals("/password/prepare") && stage.compareAndSet(4,5)) {
                            mailAttempts.incrementAndGet();
                            var prepared=call(client,"POST","/api/profile/action-confirmations",Map.of("operation","PASSWORD_CHANGE","password",Map.of("current_password",OLD,"new_password",NEXT,"confirm_password",NEXT)),200);
                            passwordId=prepared.path("id").asText();assertThat(encoder.matches(OLD,users.findById("live-mail-owner").orElseThrow().getPassword())).isTrue();
                            message="Đã gửi mã xác nhận đổi mật khẩu tới alias vừa xác minh. Nhập ở bước 3.";
                        } else if(step.equals("/password/execute") && stage.get()==5) {
                            call(client,"POST","/api/profile/action-confirmations/"+passwordId+"/execute",Map.of("confirmation_code",input.path("code").asText()),200);
                            User user=users.findById("live-mail-owner").orElseThrow();assertThat(encoder.matches(NEXT,user.getPassword()) && user.getAuthVersion()==1L).isTrue();
                            call(client,"GET","/api/auth/me",null,401);stage.set(6);done.countDown();message="Cả đổi email và mật khẩu lab đã thành công; phiên cũ đã bị thu hồi. Có thể đóng trang.";
                        } else throw new IllegalStateException();
                        response=json.writeValueAsBytes(Map.of("message",message,"stage",stage.get()));exchange.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");
                    }
                } catch(Exception error) {status=400;response=json.writeValueAsBytes(Map.of("message","Không xác nhận được bước này. Kiểm tra thứ tự, mã và hạn dùng; báo lỗi nhưng không gửi mã vào chat."));}
                exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.getResponseHeaders().set("Referrer-Policy","no-referrer");
                exchange.getResponseHeaders().set("X-Content-Type-Options","nosniff");exchange.getResponseHeaders().set("X-Frame-Options","DENY");
                exchange.sendResponseHeaders(status,response.length);try(var stream=exchange.getResponseBody()){stream.write(response);}
            });
            server.start();
            try {
                write(output.resolve("live-profile-ready.private.json"),Map.of("url","http://localhost:58069"+base,"maximum_seconds",1020));System.out.println("LIVE_PROFILE_LAB_READY");
                boolean success=done.await(1020,TimeUnit.SECONDS);
                write(output.resolve("live-profile-result.private.json"),Map.of("status",success?"LIVE_PROFILE_EMAIL_PASSWORD_PASS":"LIVE_PROFILE_INCOMPLETE","stage",stage.get(),"mail_attempts",mailAttempts.get(),
                    "lab_email_mutations",stage.get()>=4?1:0,"lab_password_mutations",stage.get()==6?1:0,"old_session_revoked",stage.get()==6,
                    "new_fits",0,"elapsed_seconds",(System.nanoTime()-started)/1e9,"population_gate","NOT_ESTABLISHED_BY_ONE_LAB_ACCOUNT"));assertThat(success).isTrue();
            } finally {server.stop(1);}
        }
    }
    com.fasterxml.jackson.databind.JsonNode call(HttpClient client,String method,String path,Object payload,int expected)throws Exception {
        if(payload!=null)csrf=call(client,"GET","/api/auth/csrf",null,200).path("token").asText();
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(20));
        if(payload==null)request.method(method,HttpRequest.BodyPublishers.noBody());
        else request.header("Content-Type","application/json").header("X-XSRF-TOKEN",csrf).method(method,HttpRequest.BodyPublishers.ofString(json.writeValueAsString(payload)));
        var response=client.send(request.build(),HttpResponse.BodyHandlers.ofString());
        if(response.statusCode()!=expected)throw new IllegalStateException("LAB_HTTP_STATUS_MISMATCH");
        return response.body().isBlank()?json.createObjectNode():json.readTree(response.body());
    }
    void write(Path path,Object document)throws Exception {Files.createFile(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));Files.writeString(path,json.writeValueAsString(document));}
    static String page(){return """
        <!doctype html><html lang="vi"><meta charset="utf-8"><title>Flare — thao tác lab qua email thật</title><body>
        <h1>Thử đổi email và mật khẩu trên tài khoản lab dùng một lần</h1><p>Không đổi mật khẩu Gmail. Chỉ database lab; không training, không bật chặn toàn cục. Thực hiện lần lượt 1 → 2 → 3. Tổng 4 email mới; alias +flare-live-lab thuộc cùng hộp thư Gmail.</p>
        <section><h2>1. Xác minh mailbox và tạo tài khoản lab</h2><button data-action="/contact/send">Gửi mã xác minh mailbox</button><input id="contact" inputmode="numeric" maxlength="6" placeholder="Mã 6 số"><button data-action="/contact/verify" data-code="contact">Xác minh và đăng nhập lab</button></section>
        <section><h2>2. Đổi email tài khoản lab sang alias +flare-live-lab</h2><button data-action="/email/prepare">Gửi 2 mã cho đổi email</button><p>Ô đầu: thư xác nhận thao tác đổi email gửi tới địa chỉ cũ. Ô sau: thư OTP xác minh địa chỉ email mới (alias).</p><input id="email-code" inputmode="numeric" maxlength="6" placeholder="Mã xác nhận thao tác"><input id="destination" inputmode="numeric" maxlength="6" placeholder="OTP email mới"><button data-action="/email/execute" data-code="email-code">Xác nhận đổi email lab</button></section>
        <section><h2>3. Đổi mật khẩu tài khoản lab</h2><button data-action="/password/prepare">Gửi mã đổi mật khẩu lab</button><input id="password-code" inputmode="numeric" maxlength="6" placeholder="Mã 6 số"><button data-action="/password/execute" data-code="password-code">Xác nhận đổi mật khẩu lab</button></section><p role="status" id="status"></p>
        <script>let pending=false;document.querySelectorAll('button').forEach(button=>button.onclick=async()=>{if(pending)return;pending=true;button.disabled=true;try{const code=button.dataset.code?document.getElementById(button.dataset.code).value:'';const destination=document.querySelector('#destination').value;const response=await fetch(location.pathname+button.dataset.action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,destination})});const value=await response.json();document.querySelector('#status').textContent=value.message;if(!response.ok)button.disabled=false;}catch(e){document.querySelector('#status').textContent='Không kết nối được lab.';}finally{pending=false;document.querySelectorAll('input').forEach(input=>input.value='');}});</script></body></html>
        """;}
}
