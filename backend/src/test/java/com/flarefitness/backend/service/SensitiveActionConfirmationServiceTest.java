package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.flarefitness.backend.dto.profile.ActionConfirmationDtos;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.entity.SensitiveActionConfirmation;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.SensitiveActionConfirmationRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import java.time.*;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

class SensitiveActionConfirmationServiceTest {
    final UserRepository users = mock(UserRepository.class);
    final SensitiveActionConfirmationRepository actions = mock(SensitiveActionConfirmationRepository.class);
    final EmailOtpService otp = mock(EmailOtpService.class);
    final ProfileService profiles = mock(ProfileService.class);
    final IpRateLimitService limits = mock(IpRateLimitService.class);
    final AuditLogService audit = mock(AuditLogService.class);
    final PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
    final Clock clock = Clock.fixed(Instant.parse("2026-10-20T00:00:00Z"), ZoneOffset.UTC);
    final UebaSessionTelemetry session = new UebaSessionTelemetry("a".repeat(64), LocalDateTime.parse("2026-10-19T23:00:00"));
    User user;
    SensitiveActionConfirmationService service;

    @BeforeEach void setup() {
        user = new User(); user.setId("lab-a"); user.setUsername("owner"); user.setEmail("owner@example.test");
        user.setEmailVerifiedAt(LocalDateTime.parse("2026-10-01T00:00:00")); user.setAuthVersion(3L);
        when(manager.getTransaction(any())).thenAnswer(i -> new SimpleTransactionStatus());
        when(users.findByUsernameIgnoreCaseForUpdate("owner")).thenReturn(Optional.of(user));
        when(otp.sensitiveActionTtlSeconds()).thenReturn(300L);
        when(actions.saveAndFlush(any())).thenAnswer(i -> i.getArgument(0));
        service = new SensitiveActionConfirmationService(users, actions, otp, profiles,
                new SensitiveActionPolicy(true, "lab-a"), limits, audit, manager, clock);
    }

    private ActionConfirmationDtos.PrepareRequest password() {
        return new ActionConfirmationDtos.PrepareRequest(ActionConfirmationDtos.Operation.PASSWORD_CHANGE, null,
                new ChangePasswordRequest("old-secret", "NewPassword1!", "NewPassword1!"));
    }
    private SensitiveActionConfirmation pending() {
        SensitiveActionConfirmation a = new SensitiveActionConfirmation();
        a.setId("11111111-1111-4111-8111-111111111111"); a.setUserId(user.getId());
        a.setSessionPseudonym(session.sessionPseudonym()); a.setAuthVersion(3L);
        a.setContactEmail(user.getEmail()); a.setContactVerifiedAt(user.getEmailVerifiedAt());
        a.setOperation("PASSWORD_CHANGE"); a.setState("PENDING"); a.setPasswordHash("encoded-only");
        a.setPolicyId(SensitiveActionPolicy.ID);
        a.setCreatedAt(LocalDateTime.now(clock)); a.setExpiresAt(LocalDateTime.now(clock).plusSeconds(300));
        when(actions.findForUpdate(a.getId())).thenReturn(Optional.of(a));
        return a;
    }
    private SensitiveActionConfirmationService.Actor actor(UebaSessionTelemetry metadata) {
        return new SensitiveActionConfirmationService.Actor("owner", "lab-a", 3L, metadata);
    }
    private ActionConfirmationDtos.ExecuteRequest code() { return new ActionConfirmationDtos.ExecuteRequest("123456", null); }

    @Test void preparesPasswordWithoutPersistingRawSecretsOrMutatingAccount() {
        when(profiles.prepareConfirmedPassword(eq(user), any())).thenReturn("encoded-only");
        var result = service.prepare(actor(session), password(), "127.0.0.1");
        var captured = ArgumentCaptor.forClass(SensitiveActionConfirmation.class);
        verify(actions).saveAndFlush(captured.capture());
        assertThat(captured.getValue().getPasswordHash()).isEqualTo("encoded-only");
        assertThat(result.confirmationEmailMasked()).isEqualTo("o***@example.test");
        verify(otp).sendSensitiveActionOtp(eq("owner@example.test"), anyString(), anyString(), eq("PASSWORD_CHANGE"), eq(null));
        verify(users, never()).save(any());
        verify(profiles, never()).applyConfirmedPassword(any(), any());
    }

    @Test void emailTargetDoesNotSelectConfirmationRecipient() {
        var body = new UpdateProfileRequest("Owner", "destination@example.test", "0935250037", null);
        when(profiles.prepareConfirmedEmail(user, body)).thenReturn("0935250037");
        service.prepare(actor(session), new ActionConfirmationDtos.PrepareRequest(
                ActionConfirmationDtos.Operation.EMAIL_CHANGE, body, null), "127.0.0.1");
        verify(otp).sendSensitiveActionOtp(eq("owner@example.test"), anyString(), anyString(),
                eq("EMAIL_CHANGE"), eq("destination@example.test"));
        verify(otp, never()).verifyOtp(any(), any(), any());
    }

    @Test void unknownVerificationProvenanceBlocksBeforeSendingOrSaving() {
        user.setEmailVerifiedAt(null);
        assertThatThrownBy(() -> service.prepare(actor(session), password(), "127.0.0.1"))
                .isInstanceOf(ConflictException.class);
        verify(actions, never()).saveAndFlush(any());
        verify(otp, never()).sendSensitiveActionOtp(any(), any(), any(), any(), any());
    }

    @Test void executesOnceAndScrubsPendingSecretOnCommit() {
        var action = pending(); String scope = SensitiveActionConfirmationService.scope(action);
        assertThat(service.execute(actor(session), action.getId(), code()).loginRequired()).isTrue();
        service.execute(actor(session), action.getId(), code());
        verify(otp, times(1)).verifySensitiveActionOtp(eq("owner@example.test"), eq(scope), anyString(), eq("123456"));
        verify(profiles, times(1)).applyConfirmedPassword(user, "encoded-only");
        assertThat(action.getPasswordHash()).isNull();
        assertThat(action.getState()).isEqualTo("COMMITTED");
        verify(audit, times(1)).success(eq("SENSITIVE_ACTION_CONFIRMED:" + SensitiveActionPolicy.ID),
                eq(user.getId()), eq(user.getId()), eq("PASSWORD_CHANGE"), eq(action.getId()));
    }

    @Test void failedOtpNeverAppliesAccountMutation() {
        var action = pending();
        doThrow(new BadRequestException("invalid")).when(otp).verifySensitiveActionOtp(any(), any(), any(), any());
        assertThatThrownBy(() -> service.execute(actor(session), action.getId(), code())).isInstanceOf(BadRequestException.class);
        verify(profiles, never()).applyConfirmedPassword(any(), any());
        assertThat(action.getState()).isEqualTo("PENDING");
        verify(manager).rollback(any());
    }

    @Test void differentSessionCannotUseEvenCorrectOtp() {
        var action = pending();
        var other = new UebaSessionTelemetry("b".repeat(64), session.sessionIssuedAt());
        assertThatThrownBy(() -> service.execute(actor(other), action.getId(), code())).isInstanceOf(ConflictException.class);
        verify(otp, never()).verifySensitiveActionOtp(any(), any(), any(), any());
    }

    @Test void expiryAndChangedAuthVersionAreRejectedBeforeOtpConsumption() {
        var action = pending(); action.setExpiresAt(LocalDateTime.now(clock));
        assertThatThrownBy(() -> service.execute(actor(session), action.getId(), code())).isInstanceOf(ConflictException.class);
        action.setExpiresAt(LocalDateTime.now(clock).plusMinutes(1)); user.setAuthVersion(4L);
        assertThatThrownBy(() -> service.execute(actor(session), action.getId(), code())).isInstanceOf(ConflictException.class);
        verify(otp, never()).verifySensitiveActionOtp(any(), any(), any(), any());
    }

    @Test void changedContactInvalidatesPendingConfirmation() {
        var action = pending(); user.setEmail("other@example.test");
        assertThatThrownBy(() -> service.execute(actor(session), action.getId(), code())).isInstanceOf(ConflictException.class);
        verify(otp, never()).verifySensitiveActionOtp(any(), any(), any(), any());
    }

    @Test void scopeBindsTargetPayloadAndOperation() {
        var action = pending(); String before = SensitiveActionConfirmationService.scope(action);
        action.setTargetEmail("other@example.test");
        assertThat(SensitiveActionConfirmationService.scope(action)).isNotEqualTo(before);
        action.setTargetEmail(null); action.setOperation("EMAIL_CHANGE");
        assertThat(SensitiveActionConfirmationService.scope(action)).isNotEqualTo(before);
    }

    @Test void unboundOrChangedPolicyCannotConsumeAValidProof() {
        var action = pending(); action.setPolicyId("legacy-unbound");
        assertThatThrownBy(() -> service.execute(actor(session), action.getId(), code())).isInstanceOf(ConflictException.class);
        verify(otp, never()).verifySensitiveActionOtp(any(), any(), any(), any());
        verifyNoInteractions(audit);
    }
}
