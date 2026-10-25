package com.flarefitness.backend.dto.siem;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.List;

/** Public SOC contracts. Raw HTTP requests and provider credentials are never returned. */
public final class PreventionDtos {
    private PreventionDtos() { }

    public enum SignatureKind { PATH_EXACT, PATH_PREFIX, SQLI, XSS, TRAVERSAL }
    public enum SignatureStatus { DRAFT, TESTED, PUBLISHING, ACTIVE, DEACTIVATING, DISABLED }

    public record CreateSignature(
            @NotNull SignatureKind kind,
            @Size(max = 8) String httpMethod,
            @Size(max = 160) String pathPrefix,
            @Size(max = 160) String matchValue,
            @NotBlank @Size(max = 16) String severity,
            @Size(max = 64) String sourceIncidentId
    ) { }

    public record Signature(
            String id, long version, SignatureKind kind, String httpMethod,
            String pathPrefix, String matchValue, String severity,
            SignatureStatus status, String action, String sourceIncidentId,
            String createdByUserId, String approvedByUserId,
            LocalDateTime createdAt, LocalDateTime updatedAt, LocalDateTime approvedAt
    ) { }

    public record TestFixture(
            @NotBlank @Size(max = 8) String httpMethod,
            @NotBlank @Size(max = 160) String requestPath,
            @Size(max = 256) String requestBody,
            boolean expectedMatch
    ) { }

    public record TestSignature(
            @NotEmpty @Size(min = 2, max = 20) List<@Valid TestFixture> fixtures
    ) { }

    public record TestResult(boolean passed, int passedCases, int totalCases,
                             String definitionHash) { }

    public record CreateIpBlock(
            @NotBlank @Size(max = 45) String ipAddress,
            @NotBlank @Size(min = 10, max = 500) String reason,
            @NotNull Long durationMinutes,
            @Size(max = 64) String incidentId
    ) { }

    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.ALWAYS)
    public record IpBlock(
            String id, String ipAddress, String reason, String sourceType,
            String incidentId, String createdByUserId, String revokedByUserId,
            LocalDateTime startedAt, LocalDateTime expiresAt, LocalDateTime revokedAt,
            long version
    ) { }

    public record IpIntelligence(
            String ipAddress, String provider, String status,
            String countryCode, String asn, String asName,
            Boolean anonymousFlag, Boolean hostingFlag,
            Integer abuseScore, Integer totalReports, Integer distinctReporters,
            LocalDateTime observedAt, LocalDateTime expiresAt, String dataProvenance
    ) { }

    public record PreventionStatus(
            long publishedVersion, Long appliedVersion, int activeSignatures,
            long activeIpBlocks, long blockedRequestsLast24h, long pendingLookups,
            String gatewayState, String ipinfoState, String abuseIpDbState
    ) { }
}
