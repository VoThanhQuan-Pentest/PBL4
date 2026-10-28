package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.PreventionDtos;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** SOC control plane; only validated definitions are ever published to the WAF. */
@Service
public class SiemPreventionService {
    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9._/-]{1,159}$");
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> SEVERITIES = Set.of("LOW", "MEDIUM", "HIGH", "URGENT");
    private static final String EMPTY_POLICY = "{\"signatures\":[],\"blocks\":[]}";

    @org.springframework.beans.factory.annotation.Value("${siem.prevention.recurrence-mode:OBSERVE}")
    private String recurrenceMode = "OBSERVE";
    @org.springframework.beans.factory.annotation.Value("${siem.prevention.protected-ips:}")
    private String protectedIps = "";
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final SiemIncidentRepository incidents;
    private final AuditLogService audit;
    private final SiemIpIntelligenceWorker intelligenceWorker;
    private final SiemPreventionGateway gateway;
    private final boolean demoEnabled;

    public SiemPreventionService(JdbcTemplate jdbc, ObjectMapper mapper,
                                 SiemIncidentRepository incidents, AuditLogService audit,
                                 SiemIpIntelligenceWorker intelligenceWorker,
                                 SiemPreventionGateway gateway,
                                 @org.springframework.beans.factory.annotation.Value(
                                     "${siem.prevention.demo-enabled:false}") boolean demoEnabled) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.incidents = incidents;
        this.audit = audit;
        this.intelligenceWorker = intelligenceWorker;
        this.gateway = gateway;
        this.demoEnabled = demoEnabled;
    }

    @jakarta.annotation.PostConstruct
    void validateRecurrenceConfiguration() {
        if(!Set.of("OBSERVE","TEMPORARY","ENFORCE").contains(recurrenceMode))
            throw new IllegalStateException("Invalid recurrence mode.");
        java.util.Arrays.stream(protectedIps.split(",")).map(String::trim).filter(v->!v.isBlank()).forEach(SiemPreventionService::canonicalManagementIp);
    }

    @Transactional(readOnly = true)
    public PageResponse<PreventionDtos.Signature> signatures(int page, int size, Authentication authentication) {
        actor(authentication);
        if (page < 0 || size < 1 || size > 100) throw new BadRequestException("Invalid signature page.");
        long count = jdbc.queryForObject("SELECT COUNT(*) FROM siem_attack_signatures", Long.class);
        List<PreventionDtos.Signature> rows = jdbc.query(
                "SELECT * FROM siem_attack_signatures ORDER BY updated_at DESC,id LIMIT ? OFFSET ?",
                SIGNATURE_MAPPER, size, (long) page * size);
        return PageResponse.from(new PageImpl<>(rows, PageRequest.of(page, size), count));
    }

    @Transactional
    public PreventionDtos.Signature create(PreventionDtos.CreateSignature input, Authentication authentication) {
        String actorId = actor(authentication);
        validateDefinition(input);
        if (input.sourceIncidentId() != null && !input.sourceIncidentId().isBlank()) {
            var incident = incidents.findById(input.sourceIncidentId())
                    .orElseThrow(() -> new ResourceNotFoundException("Source incident not found."));
            if (incident.getConclusion() != IncidentConclusion.TRUE_POSITIVE) {
                throw new BadRequestException("Only confirmed incidents may produce signatures.");
            }
        }
        String id = "sig-" + UUID.randomUUID();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                INSERT INTO siem_attack_signatures
                    (id,version,kind,http_method,path_prefix,match_value,severity,status,action,
                     source_incident_id,created_by_user_id,created_at,updated_at)
                VALUES (?,0,?,?,?,?,?,'DRAFT','BLOCK',?,?,?,?)
                """, id, input.kind().name(), blankToNull(input.httpMethod()),
                blankToNull(input.pathPrefix()), blankToNull(input.matchValue()),
                input.severity().toUpperCase(), blankToNull(input.sourceIncidentId()),
                actorId, now, now);
        audit.success("SIEM_SIGNATURE_CREATED", actorId, null, "ATTACK_SIGNATURE", id);
        return requireSignature(id);
    }

    /** Only unambiguous, already-confirmed incidents become drafts. */
    @Transactional
    public int proposeFromConfirmedIncidents() {
        record Candidate(String id, String title, String rule, String severity, String closer) { }
        List<Candidate> candidates = jdbc.query("""
                SELECT i.id,i.title,i.rule_id,i.severity,h.actor_user_id
                FROM siem_incidents i
                JOIN siem_incident_history h ON h.incident_id=i.id AND h.action='CLOSE'
                WHERE i.conclusion='TRUE_POSITIVE' AND i.last_seen>=?
                  AND h.actor_user_id IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM siem_attack_signatures s
                                  WHERE s.source_incident_id=i.id)
                ORDER BY h.ngay_tao DESC LIMIT 50
                """, (row, ignored) -> new Candidate(
                row.getString(1), row.getString(2), row.getString(3),
                row.getString(4), row.getString(5)),
                LocalDateTime.now(ZoneOffset.UTC).minusDays(30));
        int proposed = 0;
        for (Candidate item : candidates) {
            String description = (item.title() + " " + item.rule()).toUpperCase(java.util.Locale.ROOT);
            boolean sqli = description.contains("SQLI") || description.contains("SQL INJECTION");
            boolean xss = description.contains("XSS") || description.contains("CROSS SITE SCRIPT");
            boolean traversal = description.contains("TRAVERSAL");
            if ((sqli ? 1 : 0) + (xss ? 1 : 0) + (traversal ? 1 : 0) != 1) continue;
            String kind = sqli ? "SQLI" : xss ? "XSS" : "TRAVERSAL";
            String signatureId = "sig-" + UUID.randomUUID();
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
            int inserted = jdbc.update("""
                    INSERT INTO siem_attack_signatures
                        (id,version,kind,severity,status,action,source_incident_id,
                         created_by_user_id,created_at,updated_at)
                    SELECT ?,0,?,?,'DRAFT','BLOCK',?,?,?,?
                    WHERE NOT EXISTS (SELECT 1 FROM siem_attack_signatures
                                      WHERE source_incident_id=?)
                    """, signatureId, kind, item.severity(), item.id(), item.closer(),
                    now, now, item.id());
            if (inserted == 1) proposed++;
        }
        return proposed;
    }

    @Transactional
    public PreventionDtos.Signature revise(String id, long expectedVersion,
                                            PreventionDtos.CreateSignature input,
                                            Authentication authentication) {
        String actorId = higherTier(authentication);
        validateDefinition(input);
        PreventionDtos.Signature prior = requireSignature(id);
        if (prior.version() != expectedVersion) throw new ConflictException("Signature changed; refresh first.");
        if (prior.status() == PreventionDtos.SignatureStatus.ACTIVE
                || prior.status() == PreventionDtos.SignatureStatus.PUBLISHING
                || prior.status() == PreventionDtos.SignatureStatus.DEACTIVATING) {
            throw new ConflictException("Disable an active signature before editing it.");
        }
        int updated = jdbc.update("""
                UPDATE siem_attack_signatures
                SET kind=?,http_method=?,path_prefix=?,match_value=?,severity=?,
                    status='DRAFT',tested_definition_hash=NULL,approved_by_user_id=NULL,
                    approved_at=NULL,version=version+1,updated_at=?
                WHERE id=? AND version=?
                """, input.kind().name(), blankToNull(input.httpMethod()),
                blankToNull(input.pathPrefix()), blankToNull(input.matchValue()),
                input.severity().toUpperCase(), LocalDateTime.now(ZoneOffset.UTC), id, expectedVersion);
        if (updated != 1) throw new ConflictException("Signature changed; refresh first.");
        jdbc.update("DELETE FROM siem_signature_test_cases WHERE signature_id=?", id);
        audit.success("SIEM_SIGNATURE_REVISED", actorId, null, "ATTACK_SIGNATURE", id);
        return requireSignature(id);
    }

    @Transactional
    public PreventionDtos.TestResult test(String id, long expectedVersion,
                                          PreventionDtos.TestSignature input,
                                          Authentication authentication) {
        higherTier(authentication);
        PreventionDtos.Signature value = requireSignature(id);
        if (value.version() != expectedVersion) throw new ConflictException("Signature changed; refresh first.");
        if (value.status() == PreventionDtos.SignatureStatus.ACTIVE
                || value.status() == PreventionDtos.SignatureStatus.PUBLISHING
                || value.status() == PreventionDtos.SignatureStatus.DEACTIVATING) {
            throw new ConflictException("Disable an active signature before retesting it.");
        }
        if (input.fixtures() == null || input.fixtures().size() < 2 || input.fixtures().size() > 20) {
            throw new BadRequestException("Provide 2 to 20 synthetic fixtures.");
        }
        boolean positive = false, negative = false;
        List<PreventionDtos.TestFixture> fixtures = input.fixtures();
        for (var fixture : fixtures) {
            if (fixture == null || !METHODS.contains(fixture.httpMethod())
                    || !validPath(fixture.requestPath())
                    || (fixture.requestBody() != null && fixture.requestBody().length() > 256)) {
                throw new BadRequestException("Fixtures need a bounded path, method and synthetic body.");
            }
            if (fixture.expectedMatch()) positive = true;
            else negative = true;
        }
        if (!positive || !negative) throw new BadRequestException("Include matching and benign fixtures.");
        String digest = definitionHash(value);
        PreventionDtos.TestResult result = gateway.test(value, fixtures, digest);
        jdbc.update("DELETE FROM siem_signature_test_cases WHERE signature_id=?", id);
        for (var fixture : fixtures) {
            jdbc.update("""
                    INSERT INTO siem_signature_test_cases
                        (id,signature_id,http_method,request_path,request_body_sha256,
                         expected_match,created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """, "sig-test-" + UUID.randomUUID(), id, fixture.httpMethod(),
                    fixture.requestPath(),
                    fixture.requestBody() == null ? null : sha256(fixture.requestBody()),
                    fixture.expectedMatch(), LocalDateTime.now(ZoneOffset.UTC));
        }
        String next = result.passed() ? "TESTED" : "DRAFT";
        jdbc.update("""
                UPDATE siem_attack_signatures SET status=?,tested_definition_hash=?,updated_at=?
                WHERE id=?
                """, next, result.passed() ? digest : null,
                LocalDateTime.now(ZoneOffset.UTC), id);
        return result;
    }

    @Transactional
    public PreventionDtos.TestResult testDefault(String id, long expectedVersion,
                                                  Authentication authentication) {
        PreventionDtos.Signature signature = requireSignature(id);
        String method = signature.httpMethod() == null ? "GET" : signature.httpMethod();
        if (signature.pathPrefix() != null
                && Set.of(PreventionDtos.SignatureKind.SQLI,
                    PreventionDtos.SignatureKind.XSS,
                    PreventionDtos.SignatureKind.TRAVERSAL).contains(signature.kind())) {
            throw new BadRequestException("Scoped detectors require explicit synthetic fixtures.");
        }
        PreventionDtos.TestFixture positive;
        PreventionDtos.TestFixture negative;
        String benignPath = pathMatches(signature, method, "/products/safe")
                ? "/.well-known/flare-benign" : "/products/safe";
        switch (signature.kind()) {
            case PATH_EXACT -> {
                positive = new PreventionDtos.TestFixture(method, signature.matchValue(), null, true);
                negative = new PreventionDtos.TestFixture(method, benignPath, null, false);
            }
            case PATH_PREFIX -> {
                positive = new PreventionDtos.TestFixture(method, signature.matchValue() + "probe", null, true);
                negative = new PreventionDtos.TestFixture(method, benignPath, null, false);
            }
            case SQLI -> {
                positive = new PreventionDtos.TestFixture("POST", "/api/products",
                        "q=1%27+UNION+SELECT+password+FROM+users", true);
                negative = new PreventionDtos.TestFixture("POST", "/api/products",
                        "q=O%27Reilly", false);
            }
            case XSS -> {
                positive = new PreventionDtos.TestFixture("POST", "/api/products",
                        "q=%3Cscript%3Ealert(1)%3C/script%3E", true);
                negative = new PreventionDtos.TestFixture("POST", "/api/products",
                        "q=plain", false);
            }
            case TRAVERSAL -> {
                positive = new PreventionDtos.TestFixture("GET", "/../../etc/passwd", null, true);
                negative = new PreventionDtos.TestFixture("GET", "/products/safe", null, false);
            }
            default -> throw new BadRequestException("Unsupported signature kind.");
        }
        return test(id, expectedVersion, new PreventionDtos.TestSignature(List.of(positive, negative)),
                authentication);
    }

    @Transactional
    public PreventionDtos.Signature activate(String id, long expectedVersion, Authentication authentication) {
        String actorId = higherTier(authentication);
        PreventionDtos.Signature value = requireSignature(id);
        if (value.version() != expectedVersion) throw new ConflictException("Signature changed; refresh first.");
        if (value.status() != PreventionDtos.SignatureStatus.TESTED) {
            throw new BadRequestException("A passing fixture test is required before activation.");
        }
        String tested = jdbc.queryForObject(
                "SELECT tested_definition_hash FROM siem_attack_signatures WHERE id=?", String.class, id);
        if (!definitionHash(value).equals(tested)) {
            throw new BadRequestException("Signature changed after testing.");
        }
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        int changed = jdbc.update("""
                UPDATE siem_attack_signatures SET status='PUBLISHING',approved_by_user_id=?,
                    approved_at=?,updated_at=?,version=version+1 WHERE id=? AND version=?
                """, actorId, now, now, id, expectedVersion);
        if (changed != 1) throw new ConflictException("Signature changed; refresh first.");
        publish();
        audit.success("SIEM_SIGNATURE_ACTIVATION_REQUESTED", actorId, null, "ATTACK_SIGNATURE", id);
        return requireSignature(id);
    }

    @Transactional
    public PreventionDtos.Signature disable(String id, long expectedVersion, Authentication authentication) {
        String actorId = higherTier(authentication);
        PreventionDtos.Signature value = requireSignature(id);
        if (value.version() != expectedVersion) throw new ConflictException("Signature changed; refresh first.");
        String next = value.status() == PreventionDtos.SignatureStatus.ACTIVE
                || value.status() == PreventionDtos.SignatureStatus.PUBLISHING
                ? "DEACTIVATING" : "DISABLED";
        int changed = jdbc.update("""
                UPDATE siem_attack_signatures SET status=?,updated_at=?,version=version+1
                WHERE id=? AND version=?
                """, next, LocalDateTime.now(ZoneOffset.UTC), id, expectedVersion);
        if (changed != 1) throw new ConflictException("Signature changed; refresh first.");
        if ("DEACTIVATING".equals(next)) publish();
        audit.success("SIEM_SIGNATURE_DEACTIVATION_REQUESTED", actorId, null, "ATTACK_SIGNATURE", id);
        return requireSignature(id);
    }

    @Transactional
    public Map<String, Object> activePolicy() {
        try {
            Map<String,Object> latest=jdbc.queryForObject("""
                    SELECT version,checksum,policy_json FROM siem_prevention_policies
                    ORDER BY version DESC LIMIT 1
                    """, (row, number) -> Map.of(
                    "version", row.getLong("version"),
                    "checksum", row.getString("checksum"),
                    "policy_json", row.getString("policy_json")));
            try {
                if(mapper.readTree((String)latest.get("policy_json")).path("schema_version").asInt(1)<2){
                    publish();
                    return jdbc.queryForObject("SELECT version,checksum,policy_json FROM siem_prevention_policies ORDER BY version DESC LIMIT 1",
                        (row,n)->Map.of("version",row.getLong("version"),"checksum",row.getString("checksum"),"policy_json",row.getString("policy_json")));
                }
            } catch(JsonProcessingException e){throw new IllegalStateException("Invalid stored policy.",e);}
            return latest;
        } catch (EmptyResultDataAccessException absent) {
            jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
            try {
                return jdbc.queryForObject("""
                        SELECT version,checksum,policy_json FROM siem_prevention_policies
                        ORDER BY version DESC LIMIT 1
                        """, (row, number) -> Map.of("version", row.getLong("version"),
                        "checksum", row.getString("checksum"),
                        "policy_json", row.getString("policy_json")));
            } catch (EmptyResultDataAccessException stillAbsent) {
                String checksum = sha256(EMPTY_POLICY);
                jdbc.update("""
                        INSERT INTO siem_prevention_policies (checksum,policy_json,published_at)
                        VALUES (?,?,?)
                        """, checksum, EMPTY_POLICY, LocalDateTime.now(ZoneOffset.UTC));
                return jdbc.queryForObject("""
                        SELECT version,checksum,policy_json FROM siem_prevention_policies
                        ORDER BY version DESC LIMIT 1
                        """, (row, number) -> Map.of("version", row.getLong("version"),
                        "checksum", row.getString("checksum"),
                        "policy_json", row.getString("policy_json")));
            }
        }
    }

    @Transactional
    public void acknowledge(long version, String checksum) {
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        int changed = jdbc.update("""
                UPDATE siem_prevention_policies SET acknowledged_at=?
                WHERE version=? AND checksum=?
                """, now, version, checksum);
        if (changed != 1 && version != 0) {
            throw new BadRequestException("Unknown prevention policy acknowledgement.");
        }
        Long latest = jdbc.queryForObject("SELECT MAX(version) FROM siem_prevention_policies", Long.class);
        if (latest == null || version != latest) return;
        jdbc.update("""
                UPDATE siem_attack_signatures
                SET status=CASE status WHEN 'PUBLISHING' THEN 'ACTIVE'
                                       WHEN 'DEACTIVATING' THEN 'DISABLED' END,
                    updated_at=?,version=version+1
                WHERE status IN ('PUBLISHING','DEACTIVATING')
                """, now);
    }

    @Transactional
    public PreventionDtos.PreventionStatus status(Authentication authentication) {
        actor(authentication);
        Map<String, Object> latest = activePolicy();
        Long applied = jdbc.query("""
                SELECT version FROM siem_prevention_policies
                WHERE acknowledged_at IS NOT NULL ORDER BY version DESC LIMIT 1
                """, row -> row.next() ? row.getLong(1) : null);
        Integer signatures = jdbc.queryForObject(
                "SELECT COUNT(*) FROM siem_attack_signatures WHERE status='ACTIVE'", Integer.class);
        Long blocks = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)
                """, Long.class, LocalDateTime.now(ZoneOffset.UTC));
        Long denied = jdbc.queryForObject("""
                SELECT COALESCE(SUM(decision_count),0) FROM (
                    SELECT trace_id,
                        MAX(CASE WHEN event_type='AUTO_BLOCK' THEN 0
                                 WHEN event_type='RATE_LIMIT' THEN signal_count ELSE 1 END) AS decision_count
                    FROM siem_prevention_events
                    WHERE action IN ('DENY','THROTTLE') AND occurred_at>=?
                    GROUP BY trace_id
                ) AS decisions
                """, Long.class, LocalDateTime.now(ZoneOffset.UTC).minusHours(24));
        Long pendingLookups = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_lookup_requests
                WHERE status IN ('PENDING','RUNNING')
                """, Long.class);
        long published = (long) latest.get("version");
        SiemPreventionGateway.GatewayHealth health = gateway.health();
        String state = !health.available() ? "OFFLINE"
                : !"UP".equals(health.redisState()) ? "DEGRADED_REDIS"
                : applied != null && applied == published && health.version() == published
                    ? "APPLIED" : "PENDING";
        return new PreventionDtos.PreventionStatus(published, applied,
                signatures, blocks, denied, pendingLookups, state,
                intelligenceWorker.providerState("IPINFO"),
                intelligenceWorker.providerState("ABUSEIPDB"));
    }

    @Transactional(readOnly = true)
    public PageResponse<PreventionDtos.IpBlock> ipBlocks(int page, int size, Authentication authentication) {
        actor(authentication);
        if (page < 0 || size < 1 || size > 100) throw new BadRequestException("Invalid IP block page.");
        long count = jdbc.queryForObject("SELECT COUNT(*) FROM siem_ip_blocks", Long.class);
        List<PreventionDtos.IpBlock> rows = jdbc.query(
                "SELECT * FROM siem_ip_blocks ORDER BY started_at DESC,id LIMIT ? OFFSET ?",
                BLOCK_MAPPER, size, (long) page * size);
        return PageResponse.from(new PageImpl<>(rows, PageRequest.of(page, size), count));
    }

    @Transactional
    public PreventionDtos.IpBlock createIpBlock(PreventionDtos.CreateIpBlock input,
                                                 Authentication authentication) {
        String actorId = higherTier(authentication);
        String ip = canonicalPublicIp(input.ipAddress());
        if (input.durationMinutes() == null || input.durationMinutes() < 1
                || input.durationMinutes() > 1440) {
            throw new BadRequestException("IP block duration must be 1 to 1440 minutes.");
        }
        if (input.reason() == null || input.reason().trim().length() < 10
                || input.reason().trim().length() > 500) {
            throw new BadRequestException("A reason between 10 and 500 characters is required.");
        }
        if (input.incidentId() != null && !input.incidentId().isBlank()
                && !incidents.existsById(input.incidentId())) {
            throw new ResourceNotFoundException("Incident not found.");
        }
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        long existing = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks
                WHERE ip_address=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)
                """, Long.class, ip, LocalDateTime.now(ZoneOffset.UTC));
        if (existing != 0) throw new ConflictException("IP already has an active block.");
        String id = "ip-block-" + UUID.randomUUID();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("""
                INSERT INTO siem_ip_blocks
                    (id,ip_address,reason,source_type,incident_id,created_by_user_id,
                     started_at,expires_at,version)
                VALUES (?,?,?,'MANUAL',?,?,?,?,0)
                """, id, ip, input.reason().trim(), blankToNull(input.incidentId()),
                actorId, now, now.plusMinutes(input.durationMinutes()));
        publish();
        audit.success("SIEM_IP_BLOCK_CREATED", actorId, null, "IP_BLOCK", id);
        return requireBlock(id);
    }

    @Transactional
    public PreventionDtos.IpBlock revokeIpBlock(String id, long expectedVersion,
                                                 Authentication authentication) {
        String actorId = higherTier(authentication);
        PreventionDtos.IpBlock existing = requireBlock(id);
        if (existing.version() != expectedVersion) {
            throw new ConflictException("IP block changed; refresh first.");
        }
        if (existing.revokedAt() != null) return existing;
        if(existing.expiresAt()==null && jdbc.queryForObject("SELECT revoke_reason FROM siem_ip_blocks WHERE id=?",String.class,id)==null)
            throw new BadRequestException("Use the reasoned prevention/blocks revoke endpoint for UNTIL_REVOKED blocks.");
        int changed = jdbc.update("""
                UPDATE siem_ip_blocks
                SET revoked_at=?,revoked_by_user_id=?,version=version+1
                WHERE id=? AND version=?
                """, LocalDateTime.now(ZoneOffset.UTC), actorId, id, expectedVersion);
        if (changed != 1) throw new ConflictException("IP block changed; refresh first.");
        publish();
        audit.success("SIEM_IP_BLOCK_REVOKED", actorId, null, "IP_BLOCK", id);
        return requireBlock(id);
    }

    @Transactional
    public boolean blockForSignal(String address, String sourceType, String reason,
                                  String incidentId, int minutes) {
        if (!Set.of("SIGNATURE", "SCAN", "HTTP_FLOOD").contains(sourceType)
                || minutes < 1 || minutes > 60
                || reason == null || reason.length() > 500) {
            throw new BadRequestException("Invalid automatic block policy.");
        }
        String ip;
        try {
            ip = canonicalPublicIp(address);
        } catch (BadRequestException ignored) {
            return false;
        }
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        Long existing = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks
                WHERE ip_address=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)
                """, Long.class, ip, now);
        if (existing != null && existing > 0) return false;
        String id = "ip-block-" + UUID.randomUUID();
        jdbc.update("""
                INSERT INTO siem_ip_blocks
                    (id,ip_address,reason,source_type,incident_id,
                     started_at,expires_at,version)
                VALUES (?,?,?,?,?,?,?,0)
                """, id, ip, reason, sourceType, incidentId, now, now.plusMinutes(minutes));
        publish();
        return true;
    }

    @Transactional(readOnly = true)
    public List<PreventionDtos.IpIntelligence> intelligence(String address, Authentication authentication) {
        actor(authentication);
        String ip = canonicalPublicIp(address);
        return jdbc.query("""
                SELECT * FROM siem_ip_intelligence WHERE ip_address=? ORDER BY provider
                """, INTELLIGENCE_MAPPER, ip);
    }

    @Transactional(readOnly = true)
    public List<PreventionDtos.IpIntelligence> incidentIntelligence(String incidentId,
                                                                    Authentication authentication) {
        actor(authentication);
        var incident = incidents.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found."));
        if (incident.getSourceIp() == null || incident.getSourceIp().isBlank()) return List.of();
        try {
            return intelligence(incident.getSourceIp(), authentication);
        } catch (BadRequestException reservedOrInvalid) {
            return List.of();
        }
    }

    @Transactional(readOnly = true)
    public List<PreventionDtos.IpIntelligence> demoIntelligence(Authentication authentication) {
        actor(authentication);
        if (!demoEnabled) throw new ResourceNotFoundException("Local demo intelligence is disabled.");
        return jdbc.query("""
                SELECT * FROM siem_ip_intelligence
                WHERE ip_address='203.0.113.55' AND data_provenance='DEMO_ONLY'
                ORDER BY provider
                """, INTELLIGENCE_MAPPER);
    }

    @Transactional
    public List<PreventionDtos.IpIntelligence> seedDemoIntelligence(Authentication authentication) {
        String actorId = actor(authentication);
        CurrentUserPrincipal principal = (CurrentUserPrincipal) authentication.getPrincipal();
        if (!demoEnabled || !"ROLE_ADMIN".equals(
                CurrentUserPrincipal.toAuthority(principal.getUser().getRole()))) {
            throw new AccessDeniedException("Only a local-lab Admin may seed demo intelligence.");
        }
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        for (String provider : List.of("IPINFO", "ABUSEIPDB")) {
            jdbc.update("""
                    INSERT INTO siem_ip_intelligence
                        (id,ip_address,provider,status,country_code,asn,as_name,
                         anonymous_flag,hosting_flag,abuse_score,total_reports,
                         distinct_reporters,observed_at,expires_at,data_provenance)
                    VALUES (?,'203.0.113.55',?,'DEMO','ZZ','AS64500',
                            'Synthetic TEST-NET fixture',NULL,NULL,?,?,?,?,?,'DEMO_ONLY')
                    ON DUPLICATE KEY UPDATE
                        status='DEMO',country_code='ZZ',asn='AS64500',
                        as_name='Synthetic TEST-NET fixture',anonymous_flag=NULL,
                        hosting_flag=NULL,abuse_score=VALUES(abuse_score),
                        total_reports=VALUES(total_reports),
                        distinct_reporters=VALUES(distinct_reporters),
                        observed_at=VALUES(observed_at),expires_at=VALUES(expires_at),
                        data_provenance='DEMO_ONLY'
                    """, "ip-intel-" + UUID.randomUUID(), provider,
                    "ABUSEIPDB".equals(provider) ? 80 : null,
                    "ABUSEIPDB".equals(provider) ? 4 : null,
                    "ABUSEIPDB".equals(provider) ? 2 : null,
                    now, now.plusHours(1));
        }
        audit.success("SIEM_DEMO_IP_INTELLIGENCE_SEEDED", actorId, null,
                "DEMO_INTELLIGENCE", "203.0.113.55");
        return demoIntelligence(authentication);
    }

    @Transactional
    public String requestLookup(String address, String reason, Authentication authentication) {
        String actorId = actor(authentication);
        return enqueueLookup(address, reason, actorId);
    }

    @Transactional
    public void requestLookupForSignal(String address, String reason) {
        try {
            enqueueLookup(address, reason, null);
        } catch (BadRequestException ignored) {
            // Internal, loopback and test fixture addresses are never sent to providers.
        }
    }

    private String enqueueLookup(String address, String reason, String actorId) {
        String ip = canonicalPublicIp(address);
        String cleanReason = String.valueOf(reason == null ? "" : reason).trim();
        if (cleanReason.isBlank() || cleanReason.length() > 80
                || !cleanReason.matches("[A-Za-z0-9 _-]+")) {
            throw new BadRequestException("Invalid lookup reason.");
        }
        // Serialize queue admission across processes using the existing policy
        // mutex. A locking read also sees a winner committed after an enclosing
        // REPEATABLE READ transaction established its snapshot.
        jdbc.queryForObject("SELECT id FROM siem_prevention_policy_lock WHERE id=1 FOR UPDATE", Integer.class);
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        List<String> recent = jdbc.query("""
                SELECT id FROM siem_ip_lookup_requests
                WHERE ip_address=? AND requested_at>? ORDER BY requested_at DESC LIMIT 1 FOR UPDATE
                """, (row, ignored) -> row.getString(1), ip, now.minusMinutes(5));
        if (!recent.isEmpty()) return recent.getFirst();
        String id = "ip-lookup-" + UUID.randomUUID();
        jdbc.update("""
                INSERT INTO siem_ip_lookup_requests
                    (id,ip_address,reason,requested_by_user_id,status,requested_at)
                VALUES (?,?,?,?,'PENDING',?)
                """, id, ip, cleanReason, actorId, now);
        if (actorId != null) audit.success("SIEM_IP_LOOKUP_REQUESTED", actorId, null, "IP_LOOKUP", id);
        return id;
    }

    private PreventionDtos.IpBlock requireBlock(String id) {
        try {
            return jdbc.queryForObject("SELECT * FROM siem_ip_blocks WHERE id=?", BLOCK_MAPPER, id);
        } catch (EmptyResultDataAccessException absent) {
            throw new ResourceNotFoundException("IP block not found.");
        }
    }

    private static final RowMapper<PreventionDtos.IpBlock> BLOCK_MAPPER =
            (row, ignored) -> new PreventionDtos.IpBlock(
                    row.getString("id"), row.getString("ip_address"),
                    row.getString("reason"), row.getString("source_type"),
                    row.getString("incident_id"), row.getString("created_by_user_id"),
                    row.getString("revoked_by_user_id"), timestamp(row, "started_at"),
                    timestamp(row, "expires_at"), timestamp(row, "revoked_at"),
                    row.getLong("version"));

    private static final RowMapper<PreventionDtos.IpIntelligence> INTELLIGENCE_MAPPER =
            (row, ignored) -> {
                LocalDateTime expires = timestamp(row, "expires_at");
                String status = row.getString("status");
                if (expires != null && expires.isBefore(LocalDateTime.now(ZoneOffset.UTC))) status = "STALE";
                return new PreventionDtos.IpIntelligence(
                        row.getString("ip_address"), row.getString("provider"), status,
                        row.getString("country_code"), row.getString("asn"), row.getString("as_name"),
                        nullableBoolean(row, "anonymous_flag"), nullableBoolean(row, "hosting_flag"),
                        nullableInt(row, "abuse_score"), nullableInt(row, "total_reports"),
                        nullableInt(row, "distinct_reporters"), timestamp(row, "observed_at"), expires,
                        row.getString("data_provenance"));
            };

    private static Boolean nullableBoolean(ResultSet row, String column) throws SQLException {
        boolean value = row.getBoolean(column);
        return row.wasNull() ? null : value;
    }

    private static Integer nullableInt(ResultSet row, String column) throws SQLException {
        int value = row.getInt(column);
        return row.wasNull() ? null : value;
    }

    /** Reject names and reserved space before any external lookup or global block. */
    public static String canonicalPublicIp(String text) {
        String value = String.valueOf(text == null ? "" : text).trim();
        if (value.isBlank() || value.length() > 45
                || !value.matches("[0-9A-Fa-f:.]+")) {
            throw new BadRequestException("A public numeric IP address is required.");
        }
        try {
            InetAddress ip;
            if (value.indexOf(':') < 0) {
                String[] parts = value.split("\\.", -1);
                if (parts.length != 4) throw new BadRequestException("Invalid IPv4 address.");
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    if (parts[i].isBlank() || parts[i].length() > 3
                            || (parts[i].length() > 1 && parts[i].startsWith("0"))) {
                        throw new BadRequestException("Invalid IPv4 address.");
                    }
                    int part = Integer.parseInt(parts[i]);
                    if (part < 0 || part > 255) throw new BadRequestException("Invalid IPv4 address.");
                    bytes[i] = (byte) part;
                }
                ip = InetAddress.getByAddress(bytes);
            } else {
                ip = InetAddress.getByName(value);
            }
            if (ip.isAnyLocalAddress() || ip.isLoopbackAddress() || ip.isLinkLocalAddress()
                    || ip.isSiteLocalAddress() || ip.isMulticastAddress()) {
                throw new BadRequestException("Private or reserved IP is not eligible.");
            }
            if (!PublicIpEligibility.isEligible(ip)) {
                throw new BadRequestException(ip instanceof Inet6Address
                        ? "Reserved IPv6 address is not eligible." : "Reserved IP is not eligible.");
            }
            return ip.getHostAddress();
        } catch (UnknownHostException | NumberFormatException exception) {
            throw new BadRequestException("Invalid public IP address.");
        }
    }

    private void publish() {
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        List<Map<String, Object>> signatures = jdbc.query("""
                SELECT id,kind,http_method,path_prefix,match_value,action,version,tested_definition_hash
                FROM siem_attack_signatures WHERE status IN ('ACTIVE','PUBLISHING') ORDER BY id
                """, (row, ignored) -> {
                    Map<String, Object> value = new LinkedHashMap<>();
                    for (String field : List.of("id", "kind", "http_method", "path_prefix", "match_value", "action")) {
                        value.put(field, row.getString(field));
                    }
                    value.put("definition_version",row.getLong("version"));
                    value.put("definition_hash",row.getString("tested_definition_hash"));
                    return value;
                });
        Long activeBlockCount = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks
                WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)
                """, Long.class, LocalDateTime.now(ZoneOffset.UTC));
        Long revokedOverrideCount = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_ip_blocks
                WHERE revoked_at IS NOT NULL AND revoked_at>?
                """, Long.class, LocalDateTime.now(ZoneOffset.UTC).minusMinutes(20));
        List<Map<String, Object>> blocks = jdbc.query("""
                SELECT id,ip_address,expires_at,duration_type FROM siem_ip_blocks
                WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?) ORDER BY id LIMIT 5000
                """, (row, ignored) -> {
                    Map<String,Object> value = new LinkedHashMap<>();
                    value.put("id",row.getString("id"));value.put("ip_address",row.getString("ip_address"));
                    value.put("duration_type",row.getString("duration_type"));
                    LocalDateTime expires=timestamp(row,"expires_at");
                    value.put("expires_at",expires==null?null:expires.atOffset(ZoneOffset.UTC).toString());
                    return value;
                }, LocalDateTime.now(ZoneOffset.UTC));
        List<Map<String, Object>> revoked = jdbc.query("""
                SELECT id,ip_address,revoked_at FROM siem_ip_blocks
                WHERE revoked_at IS NOT NULL AND revoked_at>? ORDER BY revoked_at DESC LIMIT 5000
                """, (row, ignored) -> Map.of(
                    "id", row.getString("id"), "ip_address", row.getString("ip_address"),
                            "revoked_at", timestamp(row, "revoked_at")
                                    .atOffset(ZoneOffset.UTC).toString()),
                LocalDateTime.now(ZoneOffset.UTC).minusMinutes(20));
        if (signatures.size() > 1000) throw new BadRequestException("Too many active signatures.");
        if ((activeBlockCount != null && activeBlockCount > 5000)
                || (revokedOverrideCount != null && revokedOverrideCount > 5000)) {
            throw new BadRequestException("Prevention policy exceeds the gateway entry limit.");
        }
        try {
            String policy = mapper.copy().setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS).writeValueAsString(Map.of("schema_version", 2, "signatures", signatures,
                    "blocks", blocks, "revoked_ips", revoked));
            jdbc.update("""
                    INSERT INTO siem_prevention_policies (checksum,policy_json,published_at)
                    VALUES (?,?,?)
                    """, sha256(policy), policy, LocalDateTime.now(ZoneOffset.UTC));
            Long version=jdbc.queryForObject("SELECT MAX(version) FROM siem_prevention_policies",Long.class);
            jdbc.update("UPDATE siem_ip_blocks SET published_policy_version=? WHERE published_policy_version IS NULL AND revoked_at IS NULL",version);
            jdbc.update("UPDATE siem_ip_blocks SET revoke_policy_version=? WHERE revoke_policy_version IS NULL AND revoked_at IS NOT NULL",version);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Cannot encode prevention policy.", exception);
        }
    }


    private static String canonicalManagementIp(String value) {
        if(value==null || !value.matches("[0-9A-Fa-f:.]{2,45}"))throw new IllegalStateException("Management exclusions must be numeric IPs.");
        try{return InetAddress.getByName(value).getHostAddress();}
        catch(UnknownHostException e){throw new IllegalStateException("Invalid management exclusion.");}
    }
    private static LocalDateTime asTime(Object value) {
        if(value instanceof LocalDateTime date)return date;
        return ((java.sql.Timestamp)value).toLocalDateTime();
    }

    /** Returns true only for verified live gateway evidence, whether or not the third request has arrived. */
    @Transactional
    public boolean qualifySignatureEpisode(SiemElasticGateway.PreventionEvent event,String incidentId) {
        return qualifySignatureEpisode(event,incidentId,LocalDateTime.now(ZoneOffset.UTC));
    }
    @Transactional
    boolean qualifySignatureEpisode(SiemElasticGateway.PreventionEvent event,String incidentId,LocalDateTime now) {
        if (!"LIVE_GATEWAY".equals(event.provenance()) || !"SIGNATURE_MATCH".equals(event.type())
                || !"DENY".equals(event.action()) || event.occurredAt().isBefore(now.minusMinutes(5))
                || event.occurredAt().isAfter(now.plusMinutes(2))) return false;
        String ip;
        try { ip=canonicalPublicIp(event.sourceIp()); } catch (BadRequestException e) { return false; }
        if (java.util.Arrays.stream(protectedIps.split(",")).map(String::trim).filter(v->!v.isBlank())
                .anyMatch(v->canonicalManagementIp(v).equals(ip))) return false;
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        PreventionDtos.Signature signature;
        try { signature=requireSignature(event.ruleId()); } catch(ResourceNotFoundException e) { return false; }
        if (signature.status()!=PreventionDtos.SignatureStatus.ACTIVE) return false;
        if(signature.sourceIncidentId()!=null){
            var source=incidents.findById(signature.sourceIncidentId()).orElse(null);
            if(source==null || source.getOrigin()==com.flarefitness.backend.entity.siem.IncidentOrigin.MANUAL
                    || signature.sourceIncidentId().toLowerCase(java.util.Locale.ROOT).startsWith("soc-demo-")
                    || String.valueOf(source.getClassificationReason()).contains("DEMO_ONLY")) return false;
        }
        String digest=definitionHash(signature);
        Long approved=jdbc.queryForObject("SELECT COUNT(*) FROM siem_attack_signatures WHERE id=? AND tested_definition_hash=? AND approved_at IS NOT NULL AND approved_by_user_id IS NOT NULL",Long.class,signature.id(),digest);
        if (approved==null || approved==0) return false;
        List<String> policies=jdbc.query("SELECT policy_json FROM siem_prevention_policies WHERE version=? AND acknowledged_at IS NOT NULL AND published_at<=?",(r,n)->r.getString(1),event.policyVersion(),event.occurredAt());
        long definitionVersion=-1;
        try {
            if(policies.isEmpty()) return false;
            for(var rule:mapper.readTree(policies.getFirst()).path("signatures"))
                if(signature.id().equals(rule.path("id").asText()) && digest.equals(rule.path("definition_hash").asText())) definitionVersion=rule.path("definition_version").asLong(-1);
        } catch(JsonProcessingException e) { return false; }
        if(definitionVersion<0) return false;
        List<Map<String,Object>> prior=jdbc.queryForList("SELECT started_at,expires_at,revoked_at FROM siem_ip_blocks WHERE ip_address=? ORDER BY started_at DESC LIMIT 1",ip);
        LocalDateTime boundary=now.minusDays(7);
        if(!prior.isEmpty()) {
            Map<String,Object> block=prior.getFirst();
            LocalDateTime revoked=block.get("revoked_at")==null?null:asTime(block.get("revoked_at"));
            LocalDateTime expires=block.get("expires_at")==null?null:asTime(block.get("expires_at"));
            if(revoked==null && (expires==null || expires.isAfter(now))) return true;
            boundary=revoked==null?expires:revoked;
            if(!event.occurredAt().isAfter(boundary)) return true;
        }
        jdbc.update("INSERT IGNORE INTO siem_signature_requests (ip_address,request_id,source_event_id,signature_id,signature_version,definition_hash,policy_version,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                ip,event.traceId(),event.id(),signature.id(),definitionVersion,digest,event.policyVersion(),event.occurredAt());
        LocalDateTime lower=event.occurredAt().minusSeconds(60);
        if(!boundary.isBefore(lower)) lower=boundary.plusNanos(1000);
        Long hits=jdbc.queryForObject("SELECT COUNT(*) FROM siem_signature_requests WHERE ip_address=? AND episode_id IS NULL AND occurred_at>=? AND occurred_at<=?",Long.class,ip,lower,event.occurredAt());
        if(hits==null || hits<3 || "OBSERVE".equals(recurrenceMode)) return true;
        Long strikes=jdbc.queryForObject("SELECT COUNT(*) FROM siem_recurrence_episodes WHERE ip_address=? AND invalidated_at IS NULL AND last_seen>=?",Long.class,ip,now.minusDays(7));
        int strike=Math.toIntExact(strikes==null?1:strikes+1);
        boolean unlimited=false;
        if(strike>=4 && "ENFORCE".equals(recurrenceMode)){
            var health=gateway.health();unlimited=health.available() && health.supportsUntilRevoked();
        }
        LocalDateTime expires=unlimited?null:now.plusMinutes(strike==1?15:strike==2?60:1440);
        String blockId="ip-block-"+UUID.randomUUID(),episode="episode-"+UUID.randomUUID();
        jdbc.update("INSERT INTO siem_ip_blocks (id,ip_address,reason,source_type,incident_id,started_at,expires_at,duration_type,version) VALUES (?,?,?,'SIGNATURE',?,?,?,?,0)",
                blockId,ip,"Verified signature episode; rolling seven-day strike "+strike,incidentId,now,expires,unlimited?"UNTIL_REVOKED":"TEMPORARY");
        LocalDateTime first=jdbc.queryForObject("SELECT MIN(occurred_at) FROM siem_signature_requests WHERE ip_address=? AND episode_id IS NULL AND occurred_at>=? AND occurred_at<=?",LocalDateTime.class,ip,lower,event.occurredAt());
        jdbc.update("INSERT INTO siem_recurrence_episodes (id,ip_address,block_id,incident_id,first_seen,last_seen,created_at,policy_version,strike_number,provenance) VALUES (?,?,?,?,?,?,?,?,?,'LIVE_GATEWAY_ACTIVE_TESTED_SIGNATURE')",
                episode,ip,blockId,incidentId,first,event.occurredAt(),now,event.policyVersion(),strike);
        jdbc.update("UPDATE siem_signature_requests SET episode_id=? WHERE ip_address=? AND episode_id IS NULL AND occurred_at>=? AND occurred_at<=?",episode,ip,lower,event.occurredAt());
        publish();
        return true;
    }

    @Transactional
    public Map<String,Object> blocksWithLedger(int page,int size,Authentication authentication) {
        var blocks=ipBlocks(page,size,authentication);
        List<String> ids=blocks.content().stream().map(PreventionDtos.IpBlock::id).toList();
        List<Map<String,Object>> ledger=new ArrayList<>();
        for(String id:ids) ledger.addAll(jdbc.queryForList("SELECT e.*,b.id AS block_id,b.duration_type,b.published_policy_version,b.revoke_policy_version FROM siem_ip_blocks b LEFT JOIN siem_recurrence_episodes e ON e.block_id=b.id WHERE b.id=?",id));
        return Map.of("blocks",blocks,"ledger",ledger,"recurrence_mode",recurrenceMode,"policy",status(authentication));
    }

    public record RevokeBlock(@jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max=64) String requestId,
            @jakarta.validation.constraints.NotNull Long expectedVersion,
            @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(min=10,max=500) String reason,
            @jakarta.validation.constraints.NotBlank String outcome) { }
    @Transactional
    public PreventionDtos.IpBlock revokeBlock(String id,RevokeBlock request,Authentication authentication) {
        String actorId=higherTier(authentication);
        if(request.reason().trim().length()<10 || !Set.of("FALSE_POSITIVE","RISK_ACCEPTED").contains(request.outcome())) throw new BadRequestException("A reason and revocation outcome are required.");
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        var prior=jdbc.queryForList("SELECT * FROM siem_response_requests WHERE request_id=?",request.requestId());
        if(!prior.isEmpty()) {
            var row=prior.getFirst();
            if(!actorId.equals(row.get("actor_user_id")) || !id.equals(row.get("target_id")) || !request.reason().trim().equals(row.get("reason")) || !request.outcome().equals(row.get("outcome"))) throw new ConflictException("Request ID reused.");
            return requireBlock(id);
        }
        var block=requireBlock(id);
        if(block.version()!=request.expectedVersion()) throw new ConflictException("Block changed; refresh first.");
        if(block.revokedAt()!=null) throw new ConflictException("Block already revoked.");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        jdbc.update("INSERT INTO siem_response_requests (request_id,actor_user_id,target_id,reason,outcome,created_at) VALUES (?,?,?,?,?,?)",request.requestId(),actorId,id,request.reason().trim(),request.outcome(),now);
        jdbc.update("UPDATE siem_ip_blocks SET revoke_reason=? WHERE id=?",request.reason().trim(),id);
        if("FALSE_POSITIVE".equals(request.outcome())) jdbc.update("UPDATE siem_recurrence_episodes SET invalidated_at=?,invalidated_by_user_id=?,invalidation_reason=? WHERE block_id=? AND invalidated_at IS NULL",now,actorId,request.reason().trim(),id);
        return revokeIpBlock(id,request.expectedVersion(),authentication);
    }

    private PreventionDtos.Signature requireSignature(String id) {
        try {
            return jdbc.queryForObject("SELECT * FROM siem_attack_signatures WHERE id=?", SIGNATURE_MAPPER, id);
        } catch (EmptyResultDataAccessException absent) {
            throw new ResourceNotFoundException("Signature not found.");
        }
    }

    private static final RowMapper<PreventionDtos.Signature> SIGNATURE_MAPPER =
            (row, ignored) -> new PreventionDtos.Signature(
                    row.getString("id"), row.getLong("version"),
                    PreventionDtos.SignatureKind.valueOf(row.getString("kind")),
                    row.getString("http_method"), row.getString("path_prefix"),
                    row.getString("match_value"), row.getString("severity"),
                    PreventionDtos.SignatureStatus.valueOf(row.getString("status")),
                    row.getString("action"), row.getString("source_incident_id"),
                    row.getString("created_by_user_id"), row.getString("approved_by_user_id"),
                    timestamp(row, "created_at"), timestamp(row, "updated_at"),
                    timestamp(row, "approved_at"));

    static LocalDateTime timestamp(ResultSet row, String column) throws SQLException {
        // Security DATETIME columns store UTC clock values, not JDBC instants.
        // getTimestamp applies the connection timezone and can shift TTL/policy expiry.
        return row.getObject(column, LocalDateTime.class);
    }

    private void validateDefinition(PreventionDtos.CreateSignature input) {
        if (input == null || input.kind() == null || input.severity() == null
                || !SEVERITIES.contains(input.severity().toUpperCase())) {
            throw new BadRequestException("Invalid signature type or severity.");
        }
        if (input.httpMethod() != null && !input.httpMethod().isBlank()
                && !METHODS.contains(input.httpMethod())) {
            throw new BadRequestException("Invalid signature HTTP method.");
        }
        if (input.pathPrefix() != null && !input.pathPrefix().isBlank()
                && !validPath(input.pathPrefix())) {
            throw new BadRequestException("Invalid signature path scope.");
        }
        if (input.kind() == PreventionDtos.SignatureKind.PATH_EXACT
                || input.kind() == PreventionDtos.SignatureKind.PATH_PREFIX) {
            if (!validPath(input.matchValue())) {
                throw new BadRequestException("A bounded literal path is required.");
            }
        } else if (input.matchValue() != null && !input.matchValue().isBlank()) {
            throw new BadRequestException("This detector does not accept custom rule text.");
        }
    }

    private boolean pathMatches(PreventionDtos.Signature item, String method, String path) {
        if (item.httpMethod() != null && !item.httpMethod().equals(method)) return false;
        if (item.pathPrefix() != null && !path.startsWith(item.pathPrefix())) return false;
        return item.kind() == PreventionDtos.SignatureKind.PATH_EXACT
                ? path.equals(item.matchValue()) : path.startsWith(item.matchValue());
    }

    private String definitionHash(PreventionDtos.Signature item) {
        return sha256(item.kind() + "|" + item.httpMethod() + "|" + item.pathPrefix() + "|"
                + item.matchValue() + "|" + item.severity());
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private boolean validPath(String value) {
        return value != null && SAFE_PATH.matcher(value).matches();
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String actor(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new AccessDeniedException("SOC authentication required.");
        }
        String authority = CurrentUserPrincipal.toAuthority(principal.getUser().getRole());
        if (!Set.of("ROLE_ADMIN", "ROLE_SOC_L1", "ROLE_SOC_L2").contains(authority)) {
            throw new AccessDeniedException("SOC role required.");
        }
        return principal.getUser().getId();
    }

    private String higherTier(Authentication authentication) {
        String id = actor(authentication);
        CurrentUserPrincipal principal = (CurrentUserPrincipal) authentication.getPrincipal();
        String authority = CurrentUserPrincipal.toAuthority(principal.getUser().getRole());
        if (!"ROLE_ADMIN".equals(authority) && !"ROLE_SOC_L2".equals(authority)) {
            throw new AccessDeniedException("SOC L2 or Admin required.");
        }
        return id;
    }
}
