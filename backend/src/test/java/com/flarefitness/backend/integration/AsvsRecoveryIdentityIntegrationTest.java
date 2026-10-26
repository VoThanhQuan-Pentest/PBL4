package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

import com.flarefitness.backend.dto.admin.AdminUserRequest;
import com.flarefitness.backend.dto.auth.ForgotPasswordOtpVerifyRequest;
import com.flarefitness.backend.dto.auth.ForgotPasswordRequest;
import com.flarefitness.backend.dto.auth.OtpRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.PasswordResetTokenStore;
import com.flarefitness.backend.service.AdminService;
import com.flarefitness.backend.service.AuthService;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** SMTP is captured; identity/epoch/OTP/grant checks use real MySQL and Redis. */
@SpringBootTest(properties = "management.health.mail.enabled=false")
class AsvsRecoveryIdentityIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired UserRepository users;
    @Autowired AuthService auth;
    @Autowired AdminService admin;
    @Autowired PasswordResetTokenStore grants;
    @Autowired PasswordEncoder encoder;
    @MockitoBean JavaMailSender mail;
    private final ConcurrentHashMap<String, String> codes = new ConcurrentHashMap<>();
    private static final String OLD = "AsvsOwner!Password1";
    private static final String NEW = "AsvsOwner!Replacement2";

    @BeforeEach void captureMail() {
        codes.clear();
        doAnswer(call -> {
            SimpleMailMessage message = call.getArgument(0);
            var code = Pattern.compile("\\b[0-9]{6}\\b").matcher(message.getText());
            if (!code.find()) throw new AssertionError("Missing OTP in synthetic delivery");
            codes.put(message.getTo()[0], code.group());
            return null;
        }).when(mail).send(any(SimpleMailMessage.class));
    }

    @Test void aFreshRecoveryChallengeAndGrantResetOnlyTheirOwnerAndAreSingleUse() {
        User owner = user(null, "Nhan vien");
        auth.sendForgotPasswordOtp(new OtpRequest(null, owner.getEmail(), null), "192.0.2.71");
        String code = codes.get(owner.getEmail()); assertThat(code).isNotNull();
        String token = auth.verifyForgotPasswordOtp(new ForgotPasswordOtpVerifyRequest(owner.getEmail(), code)).resetToken();
        reset(owner.getEmail(), token);
        User changed = users.findActiveById(owner.getId()).orElseThrow();
        assertThat(encoder.matches(NEW, changed.getPassword())).isTrue();
        assertThat(changed.getAuthVersion()).isEqualTo(owner.getAuthVersion() + 1);
        assertThatThrownBy(() -> reset(owner.getEmail(), token)).isInstanceOf(BadRequestException.class);
    }

    @Test void anOtpForAPreviousEmailOwnerCannotAuthorizeANewAccount() {
        User a = user(null, "Nhan vien"); String email = a.getEmail();
        auth.sendForgotPasswordOtp(new OtpRequest(null, email, null), "192.0.2.72");
        String code = codes.get(email); assertThat(code).isNotNull();
        a.setEmail("moved-" + email); users.saveAndFlush(a);
        User b = user(email, "Nhan vien");
        assertThatThrownBy(() -> auth.verifyForgotPasswordOtp(new ForgotPasswordOtpVerifyRequest(email, code)))
                .isInstanceOf(BadRequestException.class);
        assertThat(users.findActiveById(b.getId()).orElseThrow().getPassword()).isEqualTo(b.getPassword());
    }

    @Test void aGrantForAPreviousEmailOwnerCannotResetTheNewAccount() {
        User a = user(null, "Nhan vien"); String email = a.getEmail(); String token = grants.issue(a);
        a.setEmail("moved-" + email); users.saveAndFlush(a);
        User b = user(email, "Nhan vien");
        assertThatThrownBy(() -> reset(email, token)).isInstanceOf(BadRequestException.class);
        assertThat(users.findActiveById(b.getId()).orElseThrow().getPassword()).isEqualTo(b.getPassword());
    }

    @Test void administrativeEmailChangesCannotReviveAnOlderRecoveryGrant() {
        User owner = user(null, "Nhan vien"); String email = owner.getEmail(); String token = grants.issue(owner);
        User administrator = user(null, "Admin");
        var principal = new CurrentUserPrincipal(administrator);
        var actor = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        for (String target : new String[]{"moved-" + email, email}) {
            admin.updateUser(owner.getId(), new AdminUserRequest(owner.getHoTen(), owner.getUsername(), target,
                    "", owner.getRole(), owner.getStatus(), null), actor);
        }
        assertThat(users.findActiveById(owner.getId()).orElseThrow().getAuthVersion()).isEqualTo(owner.getAuthVersion() + 2);
        assertThatThrownBy(() -> reset(email, token)).isInstanceOf(BadRequestException.class);
    }

    @Test void aStaleHashUpgradeCannotRestoreCredentialsAfterAReset() {
        User owner = user(null, "Nhan vien"); String token = grants.issue(owner);
        reset(owner.getEmail(), token);
        int updated = users.upgradePasswordHash(owner.getId(), owner.getPassword(), owner.getAuthVersion(), encoder.encode(OLD));
        assertThat(updated).isZero();
        User current = users.findActiveById(owner.getId()).orElseThrow();
        assertThat(encoder.matches(NEW, current.getPassword())).isTrue();
        assertThat(current.getAuthVersion()).isEqualTo(owner.getAuthVersion() + 1);
    }

    @Test void anAmbiguousLegacySuffixCannotAuthenticateOrMigrateTheStoredHash() {
        User owner = user(null, "Nhan vien");
        String password = "x".repeat(72);
        String legacyHash = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4).encode(password);
        owner.setPassword(legacyHash); users.saveAndFlush(owner);
        assertThatThrownBy(() -> auth.login(
                new com.flarefitness.backend.dto.auth.LoginRequest(owner.getUsername(), password + "z"),
                "192.0.2.182", "ASVS legacy boundary fixture"))
                .isInstanceOf(com.flarefitness.backend.exception.UnauthorizedException.class);
        assertThat(users.findActiveById(owner.getId()).orElseThrow().getPassword()).isEqualTo(legacyHash);
        auth.login(new com.flarefitness.backend.dto.auth.LoginRequest(owner.getUsername(), password),
                "192.0.2.182", "ASVS legacy boundary fixture");
        String migrated = users.findActiveById(owner.getId()).orElseThrow().getPassword();
        assertThat(migrated).startsWith(com.flarefitness.backend.security.BcryptSha256PasswordEncoder.PREFIX);
        assertThat(encoder.matches(password, migrated)).isTrue();
        assertThat(encoder.matches(password + "z", migrated)).isFalse();
    }

    @Test void independentRecoveryRestoresAccessAfterAnOversizedLegacyProofIsRejected() {
        User owner = user(null, "Nhan vien");
        String password = "x".repeat(72);
        owner.setPassword(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4).encode(password));
        users.saveAndFlush(owner);
        assertThatThrownBy(() -> auth.login(
                new com.flarefitness.backend.dto.auth.LoginRequest(owner.getUsername(), password + "z"),
                "192.0.2.183", "ASVS legacy recovery fixture"))
                .isInstanceOf(com.flarefitness.backend.exception.UnauthorizedException.class);
        reset(owner.getEmail(), grants.issue(owner));
        assertThat(auth.login(new com.flarefitness.backend.dto.auth.LoginRequest(owner.getUsername(), NEW),
                "192.0.2.183", "ASVS legacy recovery fixture").user().id()).isEqualTo(owner.getId());
        assertThat(encoder.matches(NEW, users.findActiveById(owner.getId()).orElseThrow().getPassword())).isTrue();
    }

    @Test void aTerminalNulCannotMigrateALegacyHashAtTheAuthenticationBoundary() {
        User owner = user(null, "Nhan vien");
        String password = "x".repeat(71);
        String legacyHash = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4).encode(password);
        owner.setPassword(legacyHash); users.saveAndFlush(owner);
        assertThatThrownBy(() -> auth.login(
                new com.flarefitness.backend.dto.auth.LoginRequest(owner.getUsername(), password + '\0'),
                "192.0.2.184", "ASVS legacy terminator fixture"))
                .isInstanceOf(com.flarefitness.backend.exception.UnauthorizedException.class);
        assertThat(users.findActiveById(owner.getId()).orElseThrow().getPassword()).isEqualTo(legacyHash);
    }

    private void reset(String email, String token) {
        auth.forgotPassword(new ForgotPasswordRequest(email, token, NEW, NEW));
    }

    private User user(String email, String role) {
        String id = "asvs-recovery-" + UUID.randomUUID();
        User user = new User(); user.setId(id); user.setUsername(id); user.setRole(role);
        user.setPassword(encoder.encode(OLD)); user.setEmail(email == null ? id + "@example.test" : email);
        user.setEmailVerifiedAt(LocalDateTime.now().withNano(0)); user.setHoTen("Synthetic recovery fixture");
        user.setStatus("Hoat dong"); user.setCreatedAt(LocalDateTime.now()); user.setDeleted(false);
        return users.saveAndFlush(user);
    }
}
