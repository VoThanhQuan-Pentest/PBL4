package com.flarefitness.backend.dto.profile;

import com.flarefitness.backend.dto.auth.CurrentUserResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.time.Instant;

public final class ActionConfirmationDtos {
    private ActionConfirmationDtos() { }
    public enum Operation { EMAIL_CHANGE, PASSWORD_CHANGE }
    public record PrepareRequest(Operation operation, @Valid UpdateProfileRequest profile,
                                 @Valid ChangePasswordRequest password) { }
    public record ExecuteRequest(
            @NotBlank @Pattern(regexp = "\\d{6}") String confirmationCode,
            @Pattern(regexp = "^$|\\d{6}") String destinationOtpCode,
            @Pattern(regexp = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}") String requestId) {
        public ExecuteRequest(String confirmationCode, String destinationOtpCode) { this(confirmationCode, destinationOtpCode, null); }
    }
    public record Challenge(String id, String operation, String confirmationEmailMasked,
                            Instant expiresAt, String policyId) { }
    public record Policy(boolean required, boolean contactAvailable, String policyId) { }
    public record Executed(String id, String operation, String state, boolean loginRequired,
                           CurrentUserResponse profile, String decisionId) {
        public Executed(String id, String operation, String state, boolean loginRequired, CurrentUserResponse profile) {
            this(id, operation, state, loginRequired, profile, null);
        }
    }
}
