package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.flarefitness.backend.exception.BadRequestException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;

/** Explicitly imported test configuration; the production artifact contains none of these routes. */
@TestConfiguration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "siem.security-events.webauthn-lab-enabled", havingValue = "true")
@Import({WebAuthnLabConfiguration.Controller.class, WebAuthnLabConfiguration.Page.class})
class WebAuthnLabConfiguration {
    // Public disposable test fixture credentials, never a production account.
    static final String USERNAME = "webauthn-readiness-owner";
    static final String PASSWORD = "Public-disposable-lab-fixture#2026";
    static int requestedPort(String value) {
        if (value == null) return 0;
        int port = Integer.parseInt(value);
        if (port < 1024 || port > 65535) throw new IllegalArgumentException("Unprivileged fixed lab port required");
        return port;
    }
    @Bean CountDownLatch webAuthnLabCompleted() { return new CountDownLatch(1); }
    @Bean WebAuthnActionProofLab webAuthnLab(StringRedisTemplate redis, ObjectMapper json) {
        return new WebAuthnActionProofLab(new RedisStore(redis), json, System::currentTimeMillis);
    }

    /** Only the read-only harness page is public. All ceremony POSTs use the existing JWT/CSRF chain. */
    @Bean @Order(0) SecurityFilterChain webAuthnLabPageSecurity(HttpSecurity http) throws Exception {
        return http.securityMatcher("/lab/webauthn", "/lab/webauthn.js")
                .authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.GET, "/lab/webauthn", "/lab/webauthn.js")
                        .permitAll().anyRequest().denyAll())
                .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(
                        "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")))
                .build();
    }

    record Finish(@NotBlank @Size(max = 43) String reference,
                  @JsonProperty("credential_json") @NotBlank @Size(max = 65_536) String credentialJson,
                  @Size(max = 32) String action, @Size(max = 512) String target) { }
    record Scope(@NotBlank @Size(max = 32) String action, @NotBlank @Size(max = 512) String target) { }

    @RestController @TestComponent @RequestMapping("/api/lab/action-proof/webauthn")
    static class Controller {
        private final WebAuthnActionProofLab lab;
        private final CountDownLatch completed;
        Controller(WebAuthnActionProofLab lab, CountDownLatch completed) { this.lab = lab; this.completed = completed; }
        @PostMapping("/register/options") WebAuthnActionProofLab.Options registerOptions(HttpServletRequest r) {
            local(r); return lab.registerOptions(ActionProofLabConfiguration.context(r));
        }
        @PostMapping("/register/finish") Map<String, Object> registerFinish(@Valid @RequestBody Finish body, HttpServletRequest r) {
            local(r); return lab.registerFinish(ActionProofLabConfiguration.context(r), body.reference(), body.credentialJson());
        }
        @PostMapping("/assert/options") WebAuthnActionProofLab.Options assertionOptions(@Valid @RequestBody Scope body, HttpServletRequest r) {
            local(r); return lab.assertionOptions(ActionProofLabConfiguration.context(r), body.action(), body.target());
        }
        @PostMapping("/assert/finish") WebAuthnActionProofLab.Verified assertionFinish(@Valid @RequestBody Finish body, HttpServletRequest r) {
            local(r); return lab.assertionFinish(ActionProofLabConfiguration.context(r), body.action(), body.target(), body.reference(), body.credentialJson());
        }
        @GetMapping("/status") Map<String, Object> status(HttpServletRequest r) { local(r); return lab.browserStatus(); }
        @PostMapping("/complete") Map<String, Object> complete(HttpServletRequest r) {
            local(r); ActionProofLabConfiguration.context(r); completed.countDown(); return lab.status();
        }
    }

    @RestController @TestComponent
    static class Page {
        private final WebAuthnActionProofLab lab;
        Page(WebAuthnActionProofLab lab) { this.lab = lab; }
        @GetMapping(value = "/lab/webauthn", produces = MediaType.TEXT_HTML_VALUE)
        String page(HttpServletRequest request) throws IOException {
            local(request);
            if (!lab.configured()) return "<!doctype html><html lang=vi><meta charset=utf-8><meta http-equiv=refresh content=1>"
                    + "<title>Flare lab đang khởi động</title><p>Máy chủ đang chuẩn bị tài khoản lab. Trang sẽ tự tải lại.</p></html>";
            return resource("webauthn-readiness.html").replace("__LIFECYCLE_PHASE__", lab.browserStatus().get("lifecycle_phase").toString());
        }
        @GetMapping(value = "/lab/webauthn.js", produces = "text/javascript")
        String script(HttpServletRequest request) throws IOException {
            local(request); return resource("webauthn-readiness.js").replace("__USERNAME__", USERNAME).replace("__PASSWORD__", PASSWORD);
        }
        private String resource(String name) throws IOException {
            try (var input = getClass().getResourceAsStream("/lab/" + name)) {
                if (input == null) throw new IOException("Lab resource missing");
                return new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
    }

    private static void local(HttpServletRequest r) {
        if (!java.util.Set.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1").contains(r.getRemoteAddr())) {
            throw new BadRequestException("Loopback lab only.");
        }
    }

    static final class RedisStore implements WebAuthnActionProofLab.Store {
        private static final DefaultRedisScript<Long> TAKE = new DefaultRedisScript<>("""
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                local t = redis.call('TIME')
                if tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000) >= tonumber(ARGV[2]) then return 0 end
                return redis.call('DEL', KEYS[1])
                """, Long.class);
        private final StringRedisTemplate redis;
        RedisStore(StringRedisTemplate redis) { this.redis = redis; }
        public void put(String key, String value, long expiresAt) {
            if (!Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, value,
                    Duration.ofMillis(Math.max(1, expiresAt - System.currentTimeMillis()))))) {
                throw new IllegalStateException("Lab pending publication failed");
            }
        }
        public String get(String key) { return redis.opsForValue().get(key); }
        public boolean take(String key, String value, long expiresAt) {
            return Long.valueOf(1).equals(redis.execute(TAKE, java.util.List.of(key), value, Long.toString(expiresAt)));
        }
    }
}
