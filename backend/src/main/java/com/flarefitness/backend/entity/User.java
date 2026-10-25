package com.flarefitness.backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbl_nguoi_dung")
public class User extends BaseEntity {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "password", nullable = false, length = 255)
    private String password;

    @Column(name = "role", nullable = false, length = 50)
    private String role;

    @Column(name = "ho_ten", nullable = false, length = 150)
    private String hoTen;

    @Column(name = "email", length = 150)
    private String email;

    /** Null for legacy users whose email verification provenance is unknown. */
    @Column(name = "email_verified_at")
    private java.time.LocalDateTime emailVerifiedAt;

    @Column(name = "trang_thai", nullable = false, length = 30)
    private String status;

    @Column(name = "is_deleted", nullable = false)
    private Boolean deleted = false;

    @Column(name = "auth_version", nullable = false)
    private Long authVersion = 0L;

    @Column(name = "soc_isolated", nullable = false)
    private Boolean socIsolated = false;

    @Column(name = "soc_isolated_until")
    private java.time.LocalDateTime socIsolatedUntil;

    public boolean isSocIsolationActive() {
        return Boolean.TRUE.equals(socIsolated) && (socIsolatedUntil == null
                || socIsolatedUntil.isAfter(java.time.LocalDateTime.now(java.time.ZoneOffset.UTC)));
    }
    public void setSocIsolated(Boolean value) { socIsolated = value; }
    public java.time.LocalDateTime getSocIsolatedUntil() { return socIsolatedUntil; }
    public void setSocIsolatedUntil(java.time.LocalDateTime value) { socIsolatedUntil = value; }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getHoTen() {
        return hoTen;
    }

    public void setHoTen(String hoTen) {
        this.hoTen = hoTen;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public java.time.LocalDateTime getEmailVerifiedAt() { return emailVerifiedAt; }

    public void setEmailVerifiedAt(java.time.LocalDateTime value) { emailVerifiedAt = value; }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Boolean getDeleted() {
        return deleted;
    }

    public void setDeleted(Boolean deleted) {
        this.deleted = deleted;
    }

    public Long getAuthVersion() {
        return authVersion;
    }

    public void setAuthVersion(Long authVersion) {
        this.authVersion = authVersion;
    }
}
