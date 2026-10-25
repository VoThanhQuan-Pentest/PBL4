package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.exception.BadRequestException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@ExtendWith(MockitoExtension.class)
class EmailOtpScopedProofTest {
    @Mock JavaMailSender mail;
    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> values;
    EmailOtpService service;
    @BeforeEach void setup() {
        service = new EmailOtpService(mail, redis, "test:otp:", 300, 60, "fixture", "fixture@example.test", "fixture", 5);
    }
    private void writable() {
        when(redis.opsForValue()).thenReturn(values);
        when(values.setIfAbsent(anyString(), eq("1"), eq(Duration.ofSeconds(60)))).thenReturn(true);
    }
    @Test void legacyEmailOtpKeepsItsNamespaceCooldownAndRecipient() {
        writable(); service.sendOtp(EmailOtpService.PURPOSE_PROFILE_EMAIL, " Owner@Example.Test ");
        verify(values).set(eq("test:otp:PROFILE_EMAIL:owner@example.test"), anyString(), eq(Duration.ofSeconds(300)));
        verify(values).setIfAbsent("test:otp:cooldown:PROFILE_EMAIL:owner@example.test", "1", Duration.ofSeconds(60));
        ArgumentCaptor<SimpleMailMessage> sent = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail).send(sent.capture()); assertThat(sent.getValue().getTo()).containsExactly("owner@example.test");
    }
    @Test void challengeScopesHaveDistinctOtpKeysAndShareTheExistingMailboxCooldown() {
        writable(); String scope = "a".repeat(64);
        service.sendLabActionProofOtp("owner@example.test", scope);
        verify(values).set(eq("test:otp:LAB_ACTION_PROOF:" + scope + ":owner@example.test"), anyString(), eq(Duration.ofSeconds(300)));
        verify(values).setIfAbsent("test:otp:cooldown:LAB_ACTION_PROOF:owner@example.test", "1", Duration.ofSeconds(60));
        doReturn(1L).when(redis).execute(any(), anyList(), any(), any(), any());
        service.verifyLabActionProofOtp("owner@example.test", scope, "123456");
        verify(redis).execute(any(), eq(List.of("test:otp:LAB_ACTION_PROOF:" + scope + ":owner@example.test",
                "test:otp:attempt:LAB_ACTION_PROOF:" + scope + ":owner@example.test",
                "test:otp:cooldown:LAB_ACTION_PROOF:owner@example.test")), eq("123456"), eq("5"), eq("300"));
    }
    @Test void malformedScopesAreRejectedBeforeMailOrRedis() {
        assertThatThrownBy(() -> service.sendLabActionProofOtp("owner@example.test", "client-chosen"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.verifyLabActionProofOtp("owner@example.test", "b".repeat(65), "123456"))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(mail, redis);
    }
    @Test void failedMailRemovesOnlyTheChallengeScopeAndItsSharedCooldown() {
        writable(); doThrow(new MailSendException("fixture")).when(mail).send(any(SimpleMailMessage.class));
        assertThatThrownBy(() -> service.sendLabActionProofOtp("owner@example.test", "c".repeat(64)))
                .isInstanceOf(BadRequestException.class);
        verify(redis).delete("test:otp:LAB_ACTION_PROOF:" + "c".repeat(64) + ":owner@example.test");
        verify(redis).delete("test:otp:cooldown:LAB_ACTION_PROOF:owner@example.test");
    }
    @Test void malformedCodesAndUnknownPurposesRetainFailClosedValidation() {
        assertThatThrownBy(() -> service.verifyLabActionProofOtp("owner@example.test", "d".repeat(64), "12345"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.sendOtp("CLIENT_SUPPLIED_PURPOSE", "owner@example.test"))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(mail, redis);
    }
}
