package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.nio.file.attribute.PosixFilePermission;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;

/** Durable MySQL outbox to NDJSON; Filebeat ships the file to Logstash. */
@Component
public class SecurityEventExportWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventExportWorker.class);
    private final SiemSecurityEventRepository repository;
    private final ObjectMapper mapper;
    private final boolean enabled;
    private final Path output;
    private final long rotateMaxBytes;

    public SecurityEventExportWorker(SiemSecurityEventRepository repository, ObjectMapper mapper,
                                     @Value("${siem.security-events.enabled:false}") boolean enabled,
                                     @Value("${siem.security-events.output-file:/var/log/flare/security-events.ndjson}")
                                     String outputFile,
                                     @Value("${siem.security-events.rotate-max-bytes:67108864}") long rotateMaxBytes) {
        this.repository = repository;
        this.mapper = mapper;
        this.enabled = enabled;
        this.output = Path.of(outputFile);
        if (rotateMaxBytes < 1) throw new IllegalArgumentException("Security event log rotation size must be positive.");
        this.rotateMaxBytes = rotateMaxBytes;
    }

    @Scheduled(initialDelayString = "${siem.security-events.export-initial-delay-ms:1000}",
            fixedDelayString = "${siem.security-events.export-interval-ms:2000}")
    @Transactional
    public void exportPending() {
        if (!enabled) return;
        try {
            ensureOutputExists();
            for (SiemSecurityEvent event : repository.findByExportedAtIsNullOrderByCreatedAtAsc(PageRequest.of(0, 200))) {
                byte[] line = (asJson(event) + "\n").getBytes(StandardCharsets.UTF_8);
                rotateIfNeeded(line.length);
                try (FileChannel channel = FileChannel.open(output, WRITE, APPEND)) {
                    ByteBuffer buffer = ByteBuffer.wrap(line);
                    while (buffer.hasRemaining()) channel.write(buffer);
                    channel.force(false);
                }
                event.setExportedAt(LocalDateTime.now(ZoneOffset.UTC));
                repository.save(event);
            }
        } catch (Exception exception) {
            LOGGER.warn("Security event export pending exceptionType={}", exception.getClass().getSimpleName());
        }
    }

    private void ensureOutputExists() throws Exception {
        if (Files.isSymbolicLink(output)) throw new IllegalStateException("Security event output cannot be a symlink.");
        if (Files.exists(output)) {
            if (!Files.isRegularFile(output)) throw new IllegalStateException("Security event output is not a file.");
            return;
        }
        Files.createFile(output);
        Files.setPosixFilePermissions(output, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ));
    }

    private void rotateIfNeeded(int nextLineBytes) throws Exception {
        long currentBytes = Files.size(output);
        if (currentBytes == 0 || currentBytes + nextLineBytes <= rotateMaxBytes) return;
        String timestamp = DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS")
                .format(LocalDateTime.now(ZoneOffset.UTC));
        Path rotated = output.resolveSibling(output.getFileName() + "." + timestamp + "." + UUID.randomUUID());
        Files.move(output, rotated);
        ensureOutputExists();
    }

    private String asJson(SiemSecurityEvent value) throws Exception {
        ObjectNode root = mapper.createObjectNode();
        // Instant always renders seconds, including :00. Filebeat's NDJSON
        // @timestamp parser rejects OffsetDateTime.toString() at exact-minute
        // instants because it abbreviates them to HH:mmZ.
        root.put("@timestamp", value.getEventTimestamp().toInstant(ZoneOffset.UTC).toString());
        ObjectNode event = root.putObject("event");
        event.put("id", value.getId());
        event.put("dataset", "flare.security");
        event.put("type", value.getEventType());
        event.put("action", value.getAction());
        event.put("outcome", value.getOutcome());
        if (value.getActorUserId() != null) root.putObject("user").put("id", value.getActorUserId());
        if (value.getTargetUserId() != null) {
            root.putObject("target").putObject("user").put("id", value.getTargetUserId());
        }
        if (value.getSourceIp() != null) root.putObject("source").put("ip", value.getSourceIp());
        if (value.getRouteGroup() != null) root.putObject("flare").put("route_group", value.getRouteGroup());
        if (value.getDemoLabel() != null) {
            ObjectNode flare = root.withObject("flare");
            flare.put("synthetic", true);
            flare.put("demo_label", value.getDemoLabel());
        }
        if (value.getHttpMethod() != null || value.getHttpStatus() != null) {
            ObjectNode http = root.putObject("http");
            if (value.getHttpMethod() != null) http.putObject("request").put("method", value.getHttpMethod());
            if (value.getHttpStatus() != null) http.putObject("response").put("status_code", value.getHttpStatus());
        }
        boolean httpSession = "HTTP_REQUEST".equals(value.getEventType())
                && Integer.valueOf(UebaSessionTelemetry.CONTRACT_VERSION).equals(value.getTelemetryContractVersion());
        boolean postLoginSession = Integer.valueOf(UebaSessionTelemetry.POST_LOGIN_CONTRACT_VERSION)
                .equals(value.getTelemetryContractVersion())
                && (("AUTH".equals(value.getEventType()) && "LOGIN".equals(value.getAction()) && "SUCCESS".equals(value.getOutcome()))
                    || (java.util.Set.of("DOMAIN_ACTION", "SENSITIVE_ACTION_ATTEMPT").contains(value.getEventType())
                        && java.util.Set.of("PASSWORD_CHANGE", "EMAIL_CHANGE").contains(value.getAction())));
        boolean investigationSession="AUTH_INVESTIGATION".equals(value.getEventType())&&value.getActorUserId()!=null
                &&Integer.valueOf(UebaSessionTelemetry.POST_LOGIN_CONTRACT_VERSION).equals(value.getTelemetryContractVersion());
        if (httpSession || postLoginSession || investigationSession) {
            root.putObject("telemetry").putObject("contract").put("version", value.getTelemetryContractVersion());
            if (httpSession) EndpointCategory.fromStored(value.getEndpointCategory()).ifPresent(category ->
                        root.withObject("http").putObject("endpoint").put("category", category.name()));
            if (value.getActorUserId() != null && !value.getActorUserId().isBlank()
                    && value.getSessionPseudonym() != null && value.getSessionPseudonym().matches("[0-9a-f]{64}")
                    && value.getSessionIssuedAt() != null
                    && !value.getSessionIssuedAt().isAfter(value.getEventTimestamp())) {
                ObjectNode session = root.putObject("session");
                session.put("pseudonym", value.getSessionPseudonym());
                session.put("issued_at", value.getSessionIssuedAt().toInstant(ZoneOffset.UTC).toString());
            }
        }
        if (value.getUserAgentFamily() != null) root.putObject("user_agent").put("family", value.getUserAgentFamily());
        if(value.getAuthRequestId()!=null){
            ObjectNode auth=root.withObject("flare").putObject("auth");auth.put("request_id",value.getAuthRequestId());
            if(value.getExecutionRequestId()!=null)auth.put("execution_request_id",value.getExecutionRequestId());
            if(value.getAuthTargetFingerprint()!=null)auth.put("target_fingerprint",value.getAuthTargetFingerprint());
            if(value.getFingerprintKeyId()!=null)auth.put("fingerprint_key_id",value.getFingerprintKeyId());
            if(value.getDenialReason()!=null)auth.put("denial_reason",value.getDenialReason());
            if(value.getChallengeReference()!=null)auth.put("challenge_reference",value.getChallengeReference());
            if(value.getRevocationReference()!=null)auth.put("revocation_reference",value.getRevocationReference());
        }
        if (value.getTraceId() != null) root.putObject("trace").put("id", value.getTraceId());
        root.putObject("observer").put("type","backend");
        if(value.getActorUsername()!=null) root.withObject("user").put("name",value.getActorUsername());
        return mapper.writeValueAsString(root);
    }
}
