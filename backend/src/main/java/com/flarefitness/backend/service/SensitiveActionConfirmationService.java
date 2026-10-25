package com.flarefitness.backend.service;

import com.flarefitness.backend.dto.profile.ActionConfirmationDtos;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.SensitiveActionConfirmation;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import com.flarefitness.backend.service.siem.PostloginDecisionService;
import com.flarefitness.backend.service.siem.SecurityEventService;
import com.flarefitness.backend.exception.ActionConfirmationCodeException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Explicit transaction authorization, independent of ML availability or score. */
@Service
public class SensitiveActionConfirmationService {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.flarefitness.backend.service.siem.SecurityEventService authInvestigationEvents;

    /** Immutable snapshot copied from verified authentication before acquiring DB locks. */
    public record Actor(String username, String userId, long authVersion, UebaSessionTelemetry session) { }
    private final UserRepository users;
    private final SensitiveActionConfirmationRepository actions;
    private final EmailOtpService otp;
    private final ProfileService profiles;
    private final SensitiveActionPolicy policy;
    private final IpRateLimitService rateLimits;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private PostloginDecisionService postlogin;

    @Autowired
    public SensitiveActionConfirmationService(UserRepository users, SensitiveActionConfirmationRepository actions,
            EmailOtpService otp, ProfileService profiles, SensitiveActionPolicy policy,
            IpRateLimitService rateLimits, AuditLogService audit, PlatformTransactionManager transactionManager,
            PostloginDecisionService postlogin) {
        this(users, actions, otp, profiles, policy, rateLimits, audit, transactionManager, Clock.systemUTC());
        this.postlogin = postlogin;
    }

    public SensitiveActionConfirmationService(UserRepository users, SensitiveActionConfirmationRepository actions,
            EmailOtpService otp, ProfileService profiles, SensitiveActionPolicy policy,
            IpRateLimitService rateLimits, AuditLogService audit, PlatformTransactionManager transactionManager) {
        this(users, actions, otp, profiles, policy, rateLimits, audit, transactionManager, Clock.systemUTC());
    }

    SensitiveActionConfirmationService(UserRepository users, SensitiveActionConfirmationRepository actions,
            EmailOtpService otp, ProfileService profiles, SensitiveActionPolicy policy,
            IpRateLimitService rateLimits, AuditLogService audit, PlatformTransactionManager transactionManager, Clock clock) {
        this.users = users; this.actions = actions; this.otp = otp; this.profiles = profiles;
        this.policy = policy; this.rateLimits = rateLimits; this.audit = audit; this.clock = clock;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public ActionConfirmationDtos.Policy status(String username) {
        User user = users.findByUsernameIgnoreCase(username).orElseThrow(this::missing);
        return new ActionConfirmationDtos.Policy(policy.requiresConfirmation(user), contactAvailable(user), SensitiveActionPolicy.ID);
    }

    /** Session metadata MUST originate from the verified-JWT request attribute, never a request body. */
    public ActionConfirmationDtos.Challenge prepare(Actor actor,
            ActionConfirmationDtos.PrepareRequest request, String ip) {
        if (actor == null || actor.session() == null) throw new ConflictException("Can dang nhap lai de xac nhan thao tac.");
        if (request == null || request.operation() == null
                || request.operation() == ActionConfirmationDtos.Operation.EMAIL_CHANGE
                && (request.profile() == null || request.password() != null)
                || request.operation() == ActionConfirmationDtos.Operation.PASSWORD_CHANGE
                && (request.password() == null || request.profile() != null)) {
            throw new BadRequestException("Chi duoc chuan bi mot thao tac hop le.");
        }
        if (postlogin != null) postlogin.beforePrepare(actor, request.operation().name());
        SensitiveActionConfirmation action = transactions.execute(tx -> {
            User user = users.findByUsernameIgnoreCaseForUpdate(actor.username()).orElseThrow(this::missing);
            requireCurrentActor(actor, user);
            requirePolicy(user);
            if (!contactAvailable(user)) throw new ConflictException("Email hien tai chua co bang chung xac minh. Chua the thuc hien thao tac.");
            if (actions.countByUserIdAndStateAndExpiresAtAfter(user.getId(), "PENDING", now()) >= 5) {
                throw new ConflictException("Da co qua nhieu yeu cau dang cho. Vui long doi het han.");
            }
            rateLimits.assertOtpSendAllowed(EmailOtpService.PURPOSE_SENSITIVE_ACTION, normalized(user.getEmail()), ip);
            SensitiveActionConfirmation pending = new SensitiveActionConfirmation();
            pending.setId(UUID.randomUUID().toString()); pending.setUserId(user.getId());
            pending.setSessionPseudonym(actor.session().sessionPseudonym()); pending.setAuthVersion(actor.authVersion());
            pending.setContactEmail(normalized(user.getEmail())); pending.setContactVerifiedAt(user.getEmailVerifiedAt());
            pending.setOperation(request.operation().name()); pending.setPolicyId(SensitiveActionPolicy.ID); pending.setState("PENDING");
            LocalDateTime created = now().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
            pending.setCreatedAt(created); pending.setExpiresAt(created.plusSeconds(otp.sensitiveActionTtlSeconds()));
            if (request.operation() == ActionConfirmationDtos.Operation.EMAIL_CHANGE) {
                var profile = request.profile();
                if (profile.hoTen() == null || profile.hoTen().isBlank() || profile.hoTen().length() > 150
                        || profile.email() == null || profile.email().length() > 150) {
                    throw new BadRequestException("Thong tin cap nhat khong hop le.");
                }
                pending.setProfileName(profile.hoTen().trim()); pending.setTargetEmail(normalized(profile.email()));
                pending.setPhone(profiles.prepareConfirmedEmail(user, profile));
            } else {
                pending.setPasswordHash(profiles.prepareConfirmedPassword(user, request.password()));
            }
            pending.setObservedAttemptId(SecurityEventService.recordedAttemptId(user.getId(), pending.getOperation(), actor.session()));
            return actions.saveAndFlush(pending);
        });
        // Do not hold database locks while waiting for SMTP. Failure leaves an
        // unusable pending record to expire, never a partially changed account.
        otp.sendSensitiveActionOtp(action.getContactEmail(), scope(action), accountScope(action.getUserId()),
                action.getOperation(), action.getTargetEmail());
        return new ActionConfirmationDtos.Challenge(action.getId(), action.getOperation(),
                masked(action.getContactEmail()), action.getExpiresAt().toInstant(java.time.ZoneOffset.UTC), SensitiveActionPolicy.ID);
    }

    public ActionConfirmationDtos.Executed execute(Actor actor, String id,
            ActionConfirmationDtos.ExecuteRequest request) {
        return execute(actor, id, request, null);
    }

    public ActionConfirmationDtos.Executed execute(Actor actor, String id,
            ActionConfirmationDtos.ExecuteRequest request, String sourceIp) {
        if (actor == null || actor.session() == null || id == null || !id.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
            throw new ConflictException("Yeu cau xac nhan khong con hieu luc.");
        }
        if(authInvestigationEvents!=null){
            var observed=actions.findById(id).orElse(null);
            if(observed!=null&&actor.userId().equals(observed.getUserId())&&actor.session().sessionPseudonym().equals(observed.getSessionPseudonym()))
                try{authInvestigationEvents.recordSensitiveExecution(actor.userId(),observed.getOperation(),id,request==null?null:request.requestId(),sourceIp);}catch(RuntimeException telemetryFailure){/* Missing observation cannot alter the accepted guard. */}
        }
        var ticket = postlogin == null ? null : postlogin.beforeExecute(actor, id, request == null ? null : request.requestId(), sourceIp);
        try {
            return transactions.execute(tx -> {
            // Stable lock order: account first, then challenge. All profile
            // mutations also lock the account, preventing stale-email bypass.
            User user = users.findByUsernameIgnoreCaseForUpdate(actor.username()).orElseThrow(this::missing);
            requireCurrentActor(actor, user);
            requirePolicy(user);
            SensitiveActionConfirmation action = actions.findForUpdate(id).orElseThrow(this::missing);
            if (!SensitiveActionPolicy.ID.equals(action.getPolicyId())) {
                throw new ConflictException("Chinh sach xac nhan da thay doi. Hay tao yeu cau moi.");
            }
            if (!user.getId().equals(action.getUserId())
                    || !actor.session().sessionPseudonym().equals(action.getSessionPseudonym())) {
                throw new ConflictException("Yeu cau khong thuoc phien hien tai.");
            }
            boolean password = "PASSWORD_CHANGE".equals(action.getOperation());
            if ("COMMITTED".equals(action.getState())) {
                if (postlogin != null) postlogin.replayedCommitted(ticket);
                return new ActionConfirmationDtos.Executed(id, action.getOperation(), "COMMITTED", password,
                        password ? null : profiles.getProfile(actor.username()), ticket == null ? null : ticket.id());
            }
            if (!"PENDING".equals(action.getState()) || !action.getExpiresAt().isAfter(now())
                    || !Objects.equals(version(user), action.getAuthVersion())
                    || !normalized(user.getEmail()).equals(action.getContactEmail())
                    || !Objects.equals(user.getEmailVerifiedAt(), action.getContactVerifiedAt())) {
                throw new ConflictException("Tai khoan hoac yeu cau da thay doi/het han. Hay tao yeu cau moi.");
            }
            if (request == null) throw new BadRequestException("Can ma xac nhan thao tac.");
            if (postlogin != null) postlogin.enforceInsideTransaction(ticket, actor, action);
            otp.verifySensitiveActionOtp(action.getContactEmail(), scope(action), accountScope(user.getId()), request.confirmationCode());
            if (!action.getExpiresAt().isAfter(now())) throw new ConflictException("Yeu cau da het han trong khi xac nhan. Hay tao yeu cau moi.");
            com.flarefitness.backend.dto.auth.CurrentUserResponse profile = null;
            if (password) {
                profiles.applyConfirmedPassword(user, action.getPasswordHash());
            } else if ("EMAIL_CHANGE".equals(action.getOperation())) {
                profile = profiles.applyConfirmedEmailChange(user, new UpdateProfileRequest(action.getProfileName(),
                        action.getTargetEmail(), action.getPhone(), request.destinationOtpCode()));
            } else {
                throw new ConflictException("Loai thao tac khong hop le.");
            }
            if (!action.getExpiresAt().isAfter(now())) throw new ConflictException("Yeu cau da het han truoc khi hoan tat. Du lieu khong duoc luu.");
            action.setState("COMMITTED"); action.setCompletedAt(now());
            scrub(action); actions.saveAndFlush(action);
            if (postlogin != null) postlogin.committed(ticket);
            audit.success("SENSITIVE_ACTION_CONFIRMED:" + action.getPolicyId(), user.getId(), user.getId(),
                    action.getOperation(), action.getId());
            return new ActionConfirmationDtos.Executed(id, action.getOperation(), "COMMITTED", password, profile, ticket == null ? null : ticket.id());
        });
        } catch (RuntimeException failure) {
            if (postlogin != null && ticket != null) {
                // The business transaction has rolled back before failure accounting is persisted.
                var action = actions.findById(id).orElse(null);
                if (action != null) postlogin.failed(ticket, actor, action.getOperation(), failure instanceof ActionConfirmationCodeException);
            }
            if(authInvestigationEvents!=null){
                var rejected=actions.findById(id).orElse(null);
                if(rejected!=null)try{authInvestigationEvents.recordSensitiveRejection(actor.userId(),rejected.getOperation(),id,failure instanceof ActionConfirmationCodeException,null,null);}catch(RuntimeException telemetryFailure){/* Existing guard remains authoritative; coverage is visible through the outbox. */}
            }
            throw failure;
        }
    }

    @Scheduled(fixedDelayString = "${app.sensitive-action-confirmation.cleanup-ms:60000}")
    public void cleanExpired() {
        transactions.executeWithoutResult(tx -> {
            actions.expireAndScrub(now());
            actions.deleteOld(now().minusHours(24));
        });
    }

    private void requirePolicy(User user) {
        if (!policy.requiresConfirmation(user)) throw new ConflictException("Xac nhan thao tac chua duoc bat cho tai khoan nay.");
    }
    private void requireCurrentActor(Actor actor, User user) {
        if (!user.getId().equals(actor.userId()) || actor.authVersion() != version(user)) {
            throw new ConflictException("Phien hoac tai khoan da thay doi. Can dang nhap lai.");
        }
    }
    private boolean contactAvailable(User user) {
        return user.getEmail() != null && !user.getEmail().isBlank()
                && user.getEmailVerifiedAt() != null && !user.getEmailVerifiedAt().isAfter(now());
    }
    private LocalDateTime now() { return LocalDateTime.now(clock); }
    private Long version(User user) { return user.getAuthVersion() == null ? 0L : user.getAuthVersion(); }
    private String normalized(String email) { return String.valueOf(email).trim().toLowerCase(Locale.ROOT); }
    private ResourceNotFoundException missing() { return new ResourceNotFoundException("Khong tim thay tai khoan hoac yeu cau."); }
    private static void scrub(SensitiveActionConfirmation action) {
        action.setPasswordHash(null); action.setProfileName(null); action.setTargetEmail(null); action.setPhone(null);
    }
    static String accountScope(String userId) { return sha("sensitive-action-account-v1\u0000" + userId); }
    static String scope(SensitiveActionConfirmation a) {
        return sha(String.join("\u0000", "sensitive-action-v1", a.getId(), a.getUserId(),
                a.getSessionPseudonym(), String.valueOf(a.getAuthVersion()), a.getOperation(), a.getPolicyId(), a.getContactEmail(),
                String.valueOf(a.getContactVerifiedAt()), String.valueOf(a.getTargetEmail()),
                String.valueOf(a.getProfileName()), String.valueOf(a.getPhone()), String.valueOf(a.getPasswordHash())));
    }
    private static String sha(String text) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static String masked(String email) {
        int split = email.lastIndexOf('@');
        return split > 0 ? email.substring(0, 1) + "***" + email.substring(split) : "***";
    }
}
