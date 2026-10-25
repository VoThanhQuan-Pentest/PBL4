package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.controller.ProfileController;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.EmailOtpService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.MethodParameter;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

/** Test-classpath only, explicitly imported and enabled; never packaged as a production auth flow. */
@TestConfiguration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "siem.security-events.action-proof-lab-enabled", havingValue = "true")
@Import({ActionProofLabConfiguration.Controller.class, ActionProofLabConfiguration.Observer.class})
class ActionProofLabConfiguration {
    static final String HEADER = "X-Lab-Action-Proof";
    static final String EVIDENCE_ATTRIBUTE = ActionProofLabConfiguration.class.getName() + ".EVIDENCE";
    static final List<String> FEATURE_NAMES = List.of("action_proof_observed", "action_proof_verified",
            "action_proof_age_seconds", "action_proof_scope_bound");

    @Bean Service actionProofLabService(StringRedisTemplate redis, EmailOtpService otp,
                                        IpRateLimitService rateLimit, ObjectMapper json) {
        return new Service(redis, otp, rateLimit, json);
    }

    record Context(String actor, long authVersion, String session, String issuedAt) { }
    record Ticket(Context context, String action, String targetDigest, long issuedAt, long expiresAt) { }
    record Evidence(String state, String reason, double ageSeconds, boolean scopeBound) {
        List<Double> values() {
            return List.of("NOT_OBSERVED".equals(state) || "UNAVAILABLE".equals(state) ? 0.0 : 1.0,
                    "VERIFIED".equals(state) ? 1.0 : 0.0, ageSeconds, scopeBound ? 1.0 : 0.0);
        }
        static Evidence missing() { return new Evidence("NOT_OBSERVED", "NO_PROOF", 0, false); }
        static Evidence invalid(String reason) { return new Evidence("INVALID", reason, 0, false); }
    }

    static Context context(HttpServletRequest request) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        Object session = request.getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE);
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)
                || !(session instanceof UebaSessionTelemetry metadata)) {
            throw new BadRequestException("Verified lab session required.");
        }
        var user = principal.getUser();
        return new Context(user.getId(), user.getAuthVersion() == null ? 0 : user.getAuthVersion(),
                metadata.sessionPseudonym(), metadata.sessionIssuedAt().toString());
    }

    static final class Service {
        private static final DefaultRedisScript<Long> TAKE = new DefaultRedisScript<>("""
                if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                local now = redis.call('TIME')
                if tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000) >= tonumber(ARGV[2]) then return 0 end
                return redis.call('DEL', KEYS[1])
                """, Long.class);
        private static final Duration LIFETIME = Duration.ofSeconds(300);
        private final StringRedisTemplate redis;
        private final EmailOtpService otp;
        private final IpRateLimitService rateLimit;
        private final ObjectMapper json;
        private final SecureRandom random = new SecureRandom();
        private final byte[] targetKey = new byte[32];
        private final Map<String, String> fixedMailboxes = new ConcurrentHashMap<>();

        Service(StringRedisTemplate redis, EmailOtpService otp, IpRateLimitService rateLimit, ObjectMapper json) {
            this.redis = redis; this.otp = otp; this.rateLimit = rateLimit; this.json = json;
            random.nextBytes(targetKey);
        }

        /** Privileged fixture bootstrap after a real OTP check; no HTTP enrollment or rebinding endpoint. */
        void bindVerifiedFixture(String actor, String email, String controlAttestationSha256) {
            if (actor == null || email == null || !email.contains("@")
                    || controlAttestationSha256 == null || !controlAttestationSha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Owned mailbox attestation required");
            }
            String normalized = email.trim().toLowerCase(Locale.ROOT);
            String previous = fixedMailboxes.putIfAbsent(actor, normalized);
            if (previous != null && !previous.equals(normalized)) throw new IllegalArgumentException("Lab binding is immutable");
        }

        String challenge(Context context, String action, String target, String ip) {
            String targetDigest = targetDigest(action, target);
            String mailbox = mailbox(context);
            rateLimit.assertOtpSendAllowed(EmailOtpService.PURPOSE_LAB_ACTION_PROOF, mailbox, ip);
            String ref = randomReference();
            otp.sendLabActionProofOtp(mailbox, hash(ref));
            store(challengeKey(ref), new Ticket(context, action, targetDigest, System.currentTimeMillis(),
                    System.currentTimeMillis() + LIFETIME.toMillis()));
            return ref;
        }

        String verify(Context context, String ref, String code) {
            if (!reference(ref)) throw new BadRequestException("Invalid lab challenge.");
            String key = challengeKey(ref);
            String encoded = redis.opsForValue().get(key);
            Ticket challenge = decode(encoded);
            if (challenge == null || !challenge.context().equals(context)) throw new BadRequestException("Invalid lab challenge.");
            otp.verifyLabActionProofOtp(mailbox(context), hash(ref), code);
            if (!Long.valueOf(1).equals(redis.execute(TAKE, List.of(key), encoded, Long.toString(challenge.expiresAt())))) {
                throw new BadRequestException("Invalid lab challenge.");
            }
            String proof = randomReference(); long now = System.currentTimeMillis();
            store(proofKey(proof), new Ticket(context, challenge.action(), challenge.targetDigest(), now, now + LIFETIME.toMillis()));
            return proof;
        }

        Evidence consume(Context context, String action, String target, String proof) {
            if (proof == null || proof.isBlank()) return Evidence.missing();
            if (!reference(proof)) return Evidence.invalid("MALFORMED");
            String key = proofKey(proof), encoded = redis.opsForValue().get(key);
            Ticket ticket = decode(encoded);
            if (ticket == null) return Evidence.invalid("EXPIRED_USED_OR_UNKNOWN");
            if (!ticket.context().equals(context) || !ticket.action().equals(action)
                    || !MessageDigest.isEqual(ticket.targetDigest().getBytes(StandardCharsets.US_ASCII),
                            targetDigest(action, target).getBytes(StandardCharsets.US_ASCII))) {
                return Evidence.invalid("BINDING_MISMATCH");
            }
            if (!Long.valueOf(1).equals(redis.execute(TAKE, List.of(key), encoded, Long.toString(ticket.expiresAt())))) {
                return Evidence.invalid("CONCURRENT_USE_OR_EXPIRED");
            }
            return new Evidence("VERIFIED", "MATCHED_ONE_USE_PROOF",
                    Math.min(300.0, (System.currentTimeMillis() - ticket.issuedAt()) / 1000.0), true);
        }

        private String mailbox(Context context) {
            String mailbox = fixedMailboxes.get(context.actor());
            if (mailbox == null) throw new BadRequestException("Lab owner channel not observed.");
            return mailbox;
        }

        private Ticket decode(String value) {
            if (value == null || value.length() > 4096) return null;
            try {
                Ticket ticket = json.readValue(value, Ticket.class);
                long now = System.currentTimeMillis();
                if (ticket.context() == null || ticket.targetDigest() == null || !ticket.targetDigest().matches("[0-9a-f]{64}")
                        || !Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE").contains(ticket.action())
                        || ticket.issuedAt() > now || ticket.expiresAt() <= now
                        || ticket.expiresAt() - ticket.issuedAt() > LIFETIME.toMillis()) return null;
                return ticket;
            } catch (Exception invalid) { return null; }
        }

        private void store(String key, Ticket ticket) {
            try {
                if (!Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, json.writeValueAsString(ticket), LIFETIME))) {
                    throw new IllegalStateException("Lab reference publication failed");
                }
            } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
                throw new IllegalStateException("Lab reference encoding failed");
            }
        }

        private String targetDigest(String action, String target) {
            if (!Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE").contains(action)
                    || target == null || target.isBlank() || target.length() > 512) {
                throw new BadRequestException("Invalid lab action target.");
            }
            String normalized = "EMAIL_CHANGE".equals(action) ? target.trim().toLowerCase(Locale.ROOT) : target;
            try {
                Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(targetKey, "HmacSHA256"));
                return HexFormat.of().formatHex(mac.doFinal((action + "\u0000" + normalized).getBytes(StandardCharsets.UTF_8)));
            } catch (java.security.GeneralSecurityException unavailable) {
                throw new IllegalStateException("Lab target binding unavailable");
            }
        }

        private String randomReference() {
            byte[] bytes = new byte[32]; random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }
        private static boolean reference(String value) { return value != null && value.matches("[A-Za-z0-9_-]{43}"); }
        String proofKey(String proof) { return "lab:ueba:action-proof:proof:" + hash(proof); }
        private String challengeKey(String ref) { return "lab:ueba:action-proof:challenge:" + hash(ref); }
        private static String hash(String value) {
            try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
            catch (java.security.NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA-256 unavailable"); }
        }
    }

    record Challenge(@NotBlank @Size(max = 32) String action, @NotBlank @Size(max = 512) String target) { }
    record Verification(@NotBlank @Size(max = 43) String challengeRef, @NotBlank @Size(max = 6) String code) { }
    record Probe(@NotBlank @Size(max = 32) String action, @NotBlank @Size(max = 512) String target,
                 @Size(max = 256) String proof) { }

    @RestController @TestComponent
    @RequestMapping("/api/lab/action-proof")
    static class Controller {
        private final Service service;
        private final IpAddressResolver addresses;
        Controller(Service service, IpAddressResolver addresses) { this.service = service; this.addresses = addresses; }
        @PostMapping("/challenge") Map<String, Object> challenge(@Valid @RequestBody Challenge body, HttpServletRequest request) {
            return Map.of("challenge_ref", service.challenge(context(request), body.action(), body.target(), addresses.resolve(request)), "ttl_seconds", 300);
        }
        @PostMapping("/verify") Map<String, Object> verify(@Valid @RequestBody Verification body, HttpServletRequest request) {
            return Map.of("proof", service.verify(context(request), body.challengeRef(), body.code()), "ttl_seconds", 300);
        }
        @PostMapping("/probe") Evidence probe(@Valid @RequestBody Probe body, HttpServletRequest request) {
            return service.consume(context(request), body.action(), body.target(), body.proof());
        }
    }

    @ControllerAdvice(assignableTypes = ProfileController.class) @TestComponent
    static class Observer extends RequestBodyAdviceAdapter {
        private final Service service;
        Observer(Service service) { this.service = service; }
        @Override public boolean supports(MethodParameter parameter, Type type, Class<? extends HttpMessageConverter<?>> converter) {
            return parameter.getDeclaringClass() == ProfileController.class;
        }
        @Override public Object afterBodyRead(Object body, HttpInputMessage input, MethodParameter parameter,
                                               Type type, Class<? extends HttpMessageConverter<?>> converter) {
            var attributes = RequestContextHolder.getRequestAttributes();
            if (!(attributes instanceof ServletRequestAttributes servlet)) return body;
            HttpServletRequest request = servlet.getRequest();
            Evidence evidence;
            try {
                if (body instanceof ChangePasswordRequest password) {
                    evidence = service.consume(context(request), "PASSWORD_CHANGE", password.newPassword(), request.getHeader(HEADER));
                } else if (body instanceof UpdateProfileRequest profile) {
                    evidence = service.consume(context(request), "EMAIL_CHANGE", profile.email(), request.getHeader(HEADER));
                } else return body;
            } catch (RuntimeException unavailable) {
                evidence = new Evidence("UNAVAILABLE", "PROOF_BACKEND_ERROR", 0, false);
            }
            request.setAttribute(EVIDENCE_ATTRIBUTE, evidence);
            return body; // Observation only; preserve the original controller/service acceptance path.
        }
    }
}
