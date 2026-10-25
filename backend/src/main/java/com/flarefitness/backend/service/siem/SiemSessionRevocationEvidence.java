package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.security.JwtTokenService;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import org.springframework.web.context.request.*;

/** Private pseudonymous proof of a completed logout, consulted only after authentication already denied. */
@Service
public class SiemSessionRevocationEvidence {
    private final JdbcTemplate jdbc;
    private final SiemAuthTelemetry telemetry;
    private final JwtTokenService tokens;
    public SiemSessionRevocationEvidence(JdbcTemplate jdbc,SiemAuthTelemetry telemetry,JwtTokenService tokens){this.jdbc=jdbc;this.telemetry=telemetry;this.tokens=tokens;}
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void record(String token,boolean all){
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null||!(auth.getPrincipal() instanceof CurrentUserPrincipal principal)||!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request)
                ||!Objects.equals(token,request.getRequest().getAttribute(JwtAuthenticationFilter.CURRENT_TOKEN_REQUEST_ATTRIBUTE)))return;
        var fingerprint=telemetry.sessionFingerprint(token);if(!all&&fingerprint==null)return;
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        // Strict second cutoff avoids treating a new login in the same second as part of logout-all.
        jdbc.update("INSERT INTO siem_session_revocation_evidence(id,user_id,session_reference,fingerprint_key_id,revoked_before,reason,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
                "auth-revoke-"+UUID.randomUUID(),principal.getUser().getId(),all?null:fingerprint.value(),all?null:fingerprint.keyId(),all?now.withNano(0):null,all?"LOGOUT_ALL":"LOGOUT",now,now.plusSeconds(tokens.getExpirationSeconds()));
    }
    @Transactional(readOnly=true)
    public String find(String signedToken,String verifiedSubject){
        var fingerprint=telemetry.sessionFingerprint(signedToken);LocalDateTime issued=LocalDateTime.ofInstant(tokens.verifiedIssuedAt(signedToken),ZoneOffset.UTC);
        var refs=jdbc.queryForList("SELECT id FROM siem_session_revocation_evidence WHERE user_id=? AND expires_at>? AND ((session_reference=? AND fingerprint_key_id=?) OR revoked_before>?) ORDER BY created_at DESC LIMIT 1",
                verifiedSubject,LocalDateTime.now(ZoneOffset.UTC),fingerprint==null?null:fingerprint.value(),fingerprint==null?null:fingerprint.keyId(),issued);
        return refs.isEmpty()?null:refs.getFirst().get("id").toString();
    }
}
