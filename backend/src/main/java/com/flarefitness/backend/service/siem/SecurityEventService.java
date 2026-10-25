package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.Set;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Server-authored, allowlisted security telemetry. No request body or raw URL is stored. */
@Service
public class SecurityEventService {
    private static final String RECORDED_ATTEMPT = SecurityEventService.class.getName() + ".recordedAttempt";
    private record RecordedAttempt(String id, String userId, String operation, String session) { }

    /** Server request attribute only; never accepts an event ID from the client. */
    public static String recordedAttemptId(String userId, String operation, UebaSessionTelemetry session) {
        if (session == null || !(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) return null;
        Object value = attributes.getRequest().getAttribute(RECORDED_ATTEMPT);
        if (!(value instanceof RecordedAttempt reference) || !reference.userId().equals(userId)
                || !reference.operation().equals(operation) || !reference.session().equals(session.sessionPseudonym())) return null;
        return reference.id();
    }
    @org.springframework.beans.factory.annotation.Autowired
    private com.flarefitness.backend.repository.UserRepository actorUsers;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private SiemAuthTelemetry authTelemetry;
    private final SiemSecurityEventRepository repository;
    private final boolean enabled;
    private final boolean postLoginEnabled;

    public SecurityEventService(SiemSecurityEventRepository repository,
                                boolean enabled) {
        this(repository, enabled, false);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SecurityEventService(SiemSecurityEventRepository repository,
                                @Value("${siem.security-events.enabled:false}") boolean enabled,
                                @Value("${siem.security-events.post-login-enabled:false}") boolean postLoginEnabled) {
        this.repository = repository;
        this.enabled = enabled;
        this.postLoginEnabled = postLoginEnabled;
    }

    public boolean isEnabled() { return enabled; }
    public boolean isPostLoginEnabled() { return enabled && postLoginEnabled; }

    @Transactional
    public void recordAuth(String action, String outcome, String actorId,
                           String targetId, String sourceIp) {
        recordAuth(action, outcome, actorId, targetId, sourceIp, null);
    }

    @Transactional
    public void recordAuth(String action, String outcome, String actorId,
                           String targetId, String sourceIp, String userAgent) {
        if (!enabled) return;
        persist("AUTH", action, outcome, actorId, targetId, sourceIp,
                "auth", null, null, SecurityEventNormalizer.userAgentFamily(userAgent));
    }

    @Transactional
    public void recordDomainAction(String action, String actorId, String targetId) {
        if (!enabled) return;
        SiemSecurityEvent event = createEvent("DOMAIN_ACTION", action, "SUCCESS", actorId, targetId,
                null, "account", null, null, null);
        if (isPostLoginEnabled() && Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE").contains(action)
                && java.util.Objects.equals(actorId, targetId)) {
            attachPostLoginSession(event, currentRequestSession(actorId));
        }
        repository.save(event);
    }

    /** The caller has issued and allowlisted this token after credential/account checks. */
    @Transactional
    public void recordSuccessfulLogin(String actorId, String sourceIp, String userAgent, UebaSessionTelemetry session) {
        if (!enabled) return;
        SiemSecurityEvent event = createEvent("AUTH", "LOGIN", "SUCCESS", actorId, actorId,
                sourceIp, "auth", null, null, SecurityEventNormalizer.userAgentFamily(userAgent));
        if (isPostLoginEnabled()) attachPostLoginSession(event, session);
        repository.save(event);
    }

    /**
     * Observation only, before validation/mutation; never a blocking decision.
     * Separate transaction retains failed attempts when the profile transaction rolls back.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSensitiveActionAttempt(String action, String actorId) {
        if (!isPostLoginEnabled() || !Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE").contains(action)) return;
        UebaSessionTelemetry session = currentRequestSession(actorId);
        if (session == null) return; // Missing coverage is never invented from IP/trace/window.
        SiemSecurityEvent event = createEvent("SENSITIVE_ACTION_ATTEMPT", action, "ATTEMPT", actorId, actorId,
                null, "account", null, null, null);
        attachPostLoginSession(event, session);
        if (event.getSessionPseudonym() != null) {
            repository.save(event);
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
                attributes.getRequest().setAttribute(RECORDED_ATTEMPT,
                        new RecordedAttempt(event.getId(), actorId, action, event.getSessionPseudonym()));
            }
        }
    }

    private static final String EXECUTION=SecurityEventService.class.getName()+".EXECUTION";
    public record RecordedExecution(String eventId,String userId,String operation,String session) { }
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void recordSensitiveExecution(String actor,String operation,String challenge,String requestId,String sourceIp) {
        if(!isPostLoginEnabled()||!Set.of("PASSWORD_CHANGE","EMAIL_CHANGE").contains(operation))return;
        var session=currentRequestSession(actor);if(session==null)return;
        var event=createEvent("AUTH_INVESTIGATION","SENSITIVE_EXECUTE","ATTEMPT",actor,actor,sourceIp,operation,null,null,null);
        attachPostLoginSession(event,session);event.setChallengeReference(challenge);
        if(requestId!=null&&requestId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))event.setExecutionRequestId(requestId);
        repository.saveAndFlush(event);
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request)
            request.getRequest().setAttribute(EXECUTION,new RecordedExecution(event.getId(),actor,operation,session.sessionPseudonym()));
    }
    public static String executionReference(String actor,String operation,String session){
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request
                &&request.getRequest().getAttribute(EXECUTION) instanceof RecordedExecution value
                &&actor.equals(value.userId())&&operation.equals(value.operation())&&session.equals(value.session()))return value.eventId();
        return null;
    }
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void recordSensitiveRejection(String actorId,String operation,String challenge,boolean otpFailure,String ip,String ua) {
        if(!enabled)return;
        var event=createEvent("AUTH_INVESTIGATION",otpFailure?"OTP_CHECK":"SENSITIVE_REJECTED","FAILURE",actorId,actorId,ip,"account",null,null,SecurityEventNormalizer.userAgentFamily(ua));
        attachPostLoginSession(event,currentRequestSession(actorId));event.setChallengeReference(challenge);
        event.setDenialReason(otpFailure?"OTP_INVALID":"SENSITIVE_ATTEMPT_REJECTED");
        event.setRouteGroup(operation);repository.save(event);
    }
    @Transactional
    public void recordSessionDenial(String target,String reason,String reference,String ip,String ua) {
        if(!enabled)return;
        var event=createEvent("AUTH_INVESTIGATION","SESSION_DENIED","DENIED",null,target,ip,"auth",null,401,SecurityEventNormalizer.userAgentFamily(ua));
        event.setDenialReason(reason);event.setRevocationReference(reference);repository.save(event);
    }
    private UebaSessionTelemetry currentRequestSession(String actorId) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (actorId == null || authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)
                || !actorId.equals(principal.getUser().getId())
                || !(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) return null;
        Object value = attributes.getRequest().getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE);
        return value instanceof UebaSessionTelemetry session ? session : null;
    }

    private void attachPostLoginSession(SiemSecurityEvent event, UebaSessionTelemetry session) {
        if (event.getActorUserId() == null || event.getActorUserId().isBlank() || session == null
                || session.sessionIssuedAt().isAfter(event.getEventTimestamp())) return;
        event.setTelemetryContractVersion(UebaSessionTelemetry.POST_LOGIN_CONTRACT_VERSION);
        event.setSessionPseudonym(session.sessionPseudonym());
        event.setSessionIssuedAt(session.sessionIssuedAt());
    }

    @Transactional
    public void recordCustomerRequest(String actorId, String sourceIp, String method,
                                      String requestPath, int status, String userAgent) {
        if (!enabled) return;
        String routeGroup = SecurityEventNormalizer.routeGroup(requestPath);
        if (routeGroup == null) return;
        persist("HTTP_REQUEST", "API_REQUEST", status >= 400 ? "FAILURE" : "SUCCESS",
                actorId, null, sourceIp, routeGroup, method, status, SecurityEventNormalizer.userAgentFamily(userAgent));
    }

    /** Legacy route-group eligibility is preserved; endpoint/session metadata is server-authored. */
    @Transactional
    public void recordCustomerRequest(String actorId, String sourceIp, String method,
                                      String requestPath, int status, String userAgent,
                                      EndpointCategory endpointCategory, UebaSessionTelemetry session) {
        if (!enabled) return;
        String routeGroup = SecurityEventNormalizer.routeGroup(requestPath);
        if (routeGroup == null) return;
        SiemSecurityEvent event = createEvent("HTTP_REQUEST", "API_REQUEST", status >= 400 ? "FAILURE" : "SUCCESS",
                actorId, null, sourceIp, routeGroup, method, status, SecurityEventNormalizer.userAgentFamily(userAgent));
        event.setTelemetryContractVersion(UebaSessionTelemetry.CONTRACT_VERSION);
        event.setEndpointCategory((endpointCategory == null ? EndpointCategory.UNRESOLVED : endpointCategory).name());
        if (session != null && session.sessionIssuedAt().compareTo(event.getEventTimestamp()) <= 0) {
            event.setSessionPseudonym(session.sessionPseudonym());
            event.setSessionIssuedAt(session.sessionIssuedAt());
        }
        repository.save(event);
    }

    private void persist(String eventType, String action, String outcome, String actorId,
                         String targetId, String sourceIp, String routeGroup, String method,
                         Integer status, String userAgentFamily) {
        repository.save(createEvent(eventType, action, outcome, actorId, targetId, sourceIp,
                routeGroup, method, status, userAgentFamily));
    }

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.flarefitness.backend.security.IpAddressResolver investigationIp;

    private SiemSecurityEvent createEvent(String eventType, String action, String outcome, String actorId,
                                         String targetId, String sourceIp, String routeGroup, String method,
                                         Integer status, String userAgentFamily) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemSecurityEvent event = new SiemSecurityEvent();
        event.setId(UUID.randomUUID().toString());
        event.setEventTimestamp(now);
        event.setActorUserId(actorId);
        var authentication=SecurityContextHolder.getContext().getAuthentication();
        if (actorId!=null && authentication!=null && authentication.getPrincipal() instanceof CurrentUserPrincipal principal
                && actorId.equals(principal.getUser().getId())) event.setActorUsername(principal.getUsername());
        else if(actorId!=null && "AUTH".equals(eventType) && "LOGIN".equals(action) && "SUCCESS".equals(outcome) && actorUsers!=null)
            actorUsers.findById(actorId).ifPresent(user->event.setActorUsername(user.getUsername()));
        event.setTargetUserId(targetId);
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes){
            if(sourceIp==null&&investigationIp!=null)sourceIp=investigationIp.resolve(attributes.getRequest());
            if(userAgentFamily==null)userAgentFamily=SecurityEventNormalizer.userAgentFamily(attributes.getRequest().getHeader("User-Agent"));
        }
        event.setSourceIp(sourceIp == null || sourceIp.length() > 64 ? null : sourceIp);
        event.setEventType(eventType);
        event.setAction(action);
        event.setOutcome(outcome);
        event.setRouteGroup(routeGroup);
        event.setHttpMethod(method);
        event.setHttpStatus(status);
        event.setUserAgentFamily(userAgentFamily);
        event.setTraceId(MDC.get("traceId"));
        SiemAuthTelemetry.attach(event);
        if(event.getFingerprintKeyId()==null&&authTelemetry!=null)event.setFingerprintKeyId(authTelemetry.keyId());
        event.setCreatedAt(now);
        return event;
    }

}
