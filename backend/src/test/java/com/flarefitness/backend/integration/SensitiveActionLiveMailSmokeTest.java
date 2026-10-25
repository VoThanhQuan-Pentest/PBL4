package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.service.EmailOtpService;
import com.sun.net.httpserver.HttpServer;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.testcontainers.containers.GenericContainer;

/** One human-entered OTP through the production service; no account mutation or fit. */
@EnabledIfEnvironmentVariable(named = "FLARE_LIVE_MAIL_SMOKE", matches = "true")
class SensitiveActionLiveMailSmokeTest {
    static final ObjectMapper JSON = new ObjectMapper();
    @Test @Timeout(570)
    void oneOwnedMailboxRoundTripThroughProductionOtpService() throws Exception {
        String recipient = System.getenv("FLARE_LIVE_MAIL_RECIPIENT");
        String sender = System.getenv("APP_MAIL_FROM");
        assertThat(recipient).isNotBlank();
        assertThat(sender).isEqualTo(System.getenv("APP_MAIL_USERNAME"));
        Path output = Path.of(System.getenv("FLARE_LIVE_MAIL_OUTPUT"));
        String capability = UUID.randomUUID().toString().replace("-", "");
        String path = "/lab/mail-confirmation/" + capability;
        String scope = hash("owned-mail-smoke-operation:" + capability);
        String account = hash("owned-mail-smoke-account:" + capability);
        var sent = new AtomicBoolean(); var verified = new AtomicBoolean();
        var attempts = new AtomicInteger(); var done = new CountDownLatch(1);
        long start = System.nanoTime();
        try (var redisContainer = new GenericContainer<>("redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99")
                .withExposedPorts(6379).withCommand("redis-server", "--requirepass", "owned-mail-smoke-only")
                .withCreateContainerCmdModifier(command -> command.getHostConfig().withMemory(128L * 1024 * 1024).withNanoCPUs(1_000_000_000L)
                        .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(6379))))) {
            redisContainer.start();
            for (var bindings : redisContainer.getContainerInfo().getNetworkSettings().getPorts().getBindings().values()) {
                for (var binding : bindings) assertThat(binding.getHostIp()).isEqualTo("127.0.0.1");
            }
            var config = new RedisStandaloneConfiguration(redisContainer.getHost(), redisContainer.getMappedPort(6379));
            config.setPassword("owned-mail-smoke-only");
            var connections = new LettuceConnectionFactory(config); connections.afterPropertiesSet(); connections.start();
            try {
                var redis = new StringRedisTemplate(connections);
                var mail = new JavaMailSenderImpl();
                mail.setHost("smtp.gmail.com"); mail.setPort(587);
                mail.setUsername(System.getenv("APP_MAIL_USERNAME")); mail.setPassword(System.getenv("APP_MAIL_PASSWORD"));
                Properties properties = mail.getJavaMailProperties();
                properties.setProperty("mail.smtp.auth", "true"); properties.setProperty("mail.smtp.starttls.enable", "true");
                properties.setProperty("mail.smtp.starttls.required", "true"); properties.setProperty("mail.smtp.ssl.checkserveridentity", "true");
                for (String name : new String[]{"connectiontimeout", "timeout", "writetimeout"}) properties.setProperty("mail.smtp." + name, "10000");
                properties.setProperty("mail.debug", "false");
                var otp = new EmailOtpService(mail, redis, "live-smoke:otp:", 300, 60,
                        System.getenv("APP_MAIL_USERNAME"), sender, System.getenv("APP_MAIL_PASSWORD"), 5);
                var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 58068), 0);
                String origin = "http://localhost:58068";
                server.createContext(path, exchange -> {
                    byte[] response; int status = 200;
                    try {
                        String requestPath = exchange.getRequestURI().getPath();
                        if (!"localhost:58068".equals(exchange.getRequestHeaders().getFirst("Host"))) throw new IllegalArgumentException();
                        if (exchange.getRequestMethod().equals("GET") && requestPath.equals(path)) {
                            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                            response = page(path).getBytes(StandardCharsets.UTF_8);
                        } else {
                            if (!exchange.getRequestMethod().equals("POST")
                                    || !origin.equals(exchange.getRequestHeaders().getFirst("Origin"))
                                    || !"application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type"))) throw new IllegalArgumentException();
                            byte[] body = exchange.getRequestBody().readNBytes(513);
                            if (body.length > 512) throw new IllegalArgumentException();
                            if (requestPath.equals(path + "/send")) {
                                if (!sent.compareAndSet(false, true)) throw new IllegalStateException();
                                // Recipient and operation are server-held, never supplied by the browser.
                                otp.sendSensitiveActionOtp(recipient, scope, account, "EMAIL_CHANGE", "readiness-only@example.test");
                                write(output.resolve("live-mail-delivery.private.json"), Map.of("smtp_accepted", true, "mail_attempts", 1));
                                response = JSON.writeValueAsBytes(Map.of("message", "Đã gửi mã. Kiểm tra Gmail và nhập mã bên dưới."));
                            } else if (requestPath.equals(path + "/verify") && sent.get() && !verified.get() && attempts.incrementAndGet() <= 5) {
                                String code = JSON.readTree(body).path("code").asText();
                                otp.verifySensitiveActionOtp(recipient, scope, account, code);
                                verified.set(true); done.countDown();
                                response = JSON.writeValueAsBytes(Map.of("message", "Đã xác nhận OTP thành công. Có thể đóng trang."));
                            } else throw new IllegalArgumentException();
                            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                        }
                    } catch (Exception error) {
                        status = 400;
                        response = JSON.writeValueAsBytes(Map.of("message", "Không xác nhận được yêu cầu. Kiểm tra mã, thời hạn hoặc báo lại lỗi; không gửi mã vào chat."));
                    }
                    exchange.getResponseHeaders().set("Cache-Control", "no-store");
                    exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
                    exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
                    exchange.sendResponseHeaders(status, response.length);
                    try (var stream = exchange.getResponseBody()) { stream.write(response); }
                });
                server.start();
                try {
                    write(output.resolve("live-mail-ready.private.json"), Map.of("url", origin + path, "maximum_seconds", 480));
                    System.out.println("LIVE_MAIL_LAB_READY");
                    boolean success = done.await(480, TimeUnit.SECONDS);
                    write(output.resolve("live-mail-result.private.json"), Map.of("status", success ? "LIVE_SMTP_AND_SCOPED_OTP_PASS" : "LIVE_MAIL_WINDOW_EXPIRED",
                            "smtp_attempted", sent.get(), "human_entered_otp_verified", verified.get(), "verify_attempts", attempts.get(),
                            "account_mutations", 0, "new_fits", 0, "elapsed_seconds", (System.nanoTime() - start) / 1e9,
                            "scope", "Production EmailOtpService + real SMTP/Redis; not profile-mutation or population-gate evidence"));
                    assertThat(success).isTrue();
                } finally { server.stop(1); }
            } finally { connections.destroy(); }
        }
    }
    static String hash(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    }
    static void write(Path path, Object value) throws Exception {
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(path, JSON.writeValueAsString(value));
    }
    static String page(String path) {
        return """
                <!doctype html><html lang="vi"><meta charset="utf-8"><title>Flare — kiểm tra OTP email</title>
                <body><h1>Kiểm tra gửi và xác nhận OTP email thật</h1>
                <p>Chỉ mailbox lab đã chốt. Không đổi email/mật khẩu, không training. Thao tác trong thư là mô phỏng tới readiness-only@example.test.</p>
                <button id="send">Gửi 1 mã OTP kiểm tra</button><form id="verify"><label>Mã 6 số trong email:
                <input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
                <button>Xác nhận mã</button></form><p id="status" role="status"></p>
                <script>
                const base = location.pathname;
                async function send(suffix, data) {
                  const response = await fetch(base + suffix, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
                  const value = await response.json();document.querySelector('#status').textContent=value.message;
                }
                document.querySelector('#send').onclick=async event=>{event.target.disabled=true;try{await send('/send',{});}catch(e){document.querySelector('#status').textContent='Không kết nối được lab.';}};
                document.querySelector('#verify').onsubmit=async event=>{event.preventDefault();const input=document.querySelector('#code');try{await send('/verify',{code:input.value});}finally{input.value='';}};
                </script></body></html>
                """;
    }
}
