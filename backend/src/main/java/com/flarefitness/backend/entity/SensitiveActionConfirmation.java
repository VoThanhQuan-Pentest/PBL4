package com.flarefitness.backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

/** Pending business data only. Never stores an OTP, raw token or plaintext password. */
@Entity
@Table(name = "sensitive_action_confirmations")
public class SensitiveActionConfirmation {
    @Column(name = "observed_attempt_id", length = 64) private String observedAttemptId;
    public String getObservedAttemptId() { return observedAttemptId; }
    public void setObservedAttemptId(String value) { observedAttemptId = value; }
    @Id @Column(length = 36, nullable = false) private String id;
    @Column(name = "user_id", length = 64, nullable = false) private String userId;
    @Column(name = "session_pseudonym", length = 64, nullable = false) private String sessionPseudonym;
    @Column(name = "auth_version", nullable = false) private Long authVersion;
    @Column(name = "contact_email", length = 150, nullable = false) private String contactEmail;
    @Column(name = "contact_verified_at", nullable = false) private LocalDateTime contactVerifiedAt;
    @Column(length = 24, nullable = false) private String operation;
    @Column(name = "policy_id", length = 96, nullable = false) private String policyId;
    @Column(name = "profile_name", length = 150) private String profileName;
    @Column(name = "target_email", length = 150) private String targetEmail;
    @Column(length = 32) private String phone;
    @Column(name = "password_hash", length = 255) private String passwordHash;
    @Column(length = 16, nullable = false) private String state;
    @Column(name = "created_at", nullable = false) private LocalDateTime createdAt;
    @Column(name = "expires_at", nullable = false) private LocalDateTime expiresAt;
    @Column(name = "completed_at") private LocalDateTime completedAt;
    @Version @Column(nullable = false) private Long version;

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getUserId() { return userId; }
    public void setUserId(String value) { userId = value; }
    public String getSessionPseudonym() { return sessionPseudonym; }
    public void setSessionPseudonym(String value) { sessionPseudonym = value; }
    public Long getAuthVersion() { return authVersion; }
    public void setAuthVersion(Long value) { authVersion = value; }
    public String getContactEmail() { return contactEmail; }
    public void setContactEmail(String value) { contactEmail = value; }
    public LocalDateTime getContactVerifiedAt() { return contactVerifiedAt; }
    public void setContactVerifiedAt(LocalDateTime value) { contactVerifiedAt = value; }
    public String getOperation() { return operation; }
    public void setOperation(String value) { operation = value; }
    public String getPolicyId() { return policyId; }
    public void setPolicyId(String value) { policyId = value; }
    public String getProfileName() { return profileName; }
    public void setProfileName(String value) { profileName = value; }
    public String getTargetEmail() { return targetEmail; }
    public void setTargetEmail(String value) { targetEmail = value; }
    public String getPhone() { return phone; }
    public void setPhone(String value) { phone = value; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String value) { passwordHash = value; }
    public String getState() { return state; }
    public void setState(String value) { state = value; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime value) { createdAt = value; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime value) { expiresAt = value; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime value) { completedAt = value; }
}
