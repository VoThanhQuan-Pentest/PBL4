package com.flarefitness.backend.dto.siem;

import jakarta.validation.constraints.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Additive SOC contract. No credentials, OTP or personal profile payloads. */
public final class PostloginDtos {
    private PostloginDtos() { }
    public record PolicyStatus(String mode,String scope,String provenance,String modelVersion,long version,
                               boolean operatorHold,int maximumHoldSeconds,boolean otpRequired) { }
    public record Summary(String id,String userId,String operation,String mode,String decision,String outcome,
            String context,Double normalPercentile,String incidentId,Instant createdAt,Instant holdExpiresAt,long version) { }
    public record Detail(Summary summary,String policyId,long policyVersion,String modelVersion,String modelSha256,
            String manifestSha256,boolean baselineEstablished,int trustedWindowCount,List<String> reasons,
            Map<String,Object> evidence,Map<String,Object> snapshot,boolean holdActive,Instant releasedAt,
            String releasedBy,String releaseReason,List<Review> reviews) { }
    public record Review(String id,String actorId,String verdict,String reason,Instant createdAt) { }
    public enum Verdict { LEGITIMATE, CONFIRMED_ABUSE, UNDETERMINED }
    public record Release(@NotNull @PositiveOrZero Long expectedVersion,@NotBlank @Size(min=10,max=1000) String reason) { }
    public record ReviewRequest(@NotNull @PositiveOrZero Long expectedVersion,@NotNull Verdict verdict,
                                @NotBlank @Size(min=10,max=1000) String reason) { }
}
