package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.TooManyRequestsException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

class SensitiveActionOtpTest {
    final JavaMailSender mail = mock(JavaMailSender.class);
    final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked") final ValueOperations<String, String> values = mock(ValueOperations.class);
    final String scope = "a".repeat(64), account = "b".repeat(64);
    EmailOtpService service;
    @BeforeEach void setup() {
        service = new EmailOtpService(mail, redis, "test:", 900, 10,
                "fixture", "fixture@example.test", "fixture", 99);
    }
    @Test void clampsLifetimeAndCooldownAndShowsOperationWithoutChoosingDestinationAsRecipient() {
        when(redis.opsForValue()).thenReturn(values);
        when(values.setIfAbsent(anyString(), eq("1"), eq(Duration.ofSeconds(60)))).thenReturn(true);
        service.sendSensitiveActionOtp("owner@example.test", scope, account, "EMAIL_CHANGE", "destination@example.test");
        verify(values).set(eq("test:SENSITIVE_ACTION:" + scope + ":owner@example.test"), anyString(), eq(Duration.ofSeconds(300)));
        verify(redis, never()).delete("test:attempt:SENSITIVE_ACTION:" + account + ":owner@example.test");
        var message = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail).send(message.capture());
        assertThat(message.getValue().getTo()).containsExactly("owner@example.test");
        assertThat(message.getValue().getText()).contains("destination@example.test", "300 giay");
    }
    @Test void accountLockSurvivesNewChallengeAndPreventsSending() {
        when(redis.opsForValue()).thenReturn(values);
        when(values.get("test:attempt:SENSITIVE_ACTION:" + account + ":owner@example.test")).thenReturn("5");
        assertThatThrownBy(() -> service.sendSensitiveActionOtp("owner@example.test", scope, account, "PASSWORD_CHANGE", null))
                .isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(mail);
    }
    @Test void verificationUsesChallengeCodeAndAccountFailureBudgetWithFiveAttemptMaximum() {
        doReturn(1L).when(redis).execute(any(), anyList(), any(), any(), any());
        service.verifySensitiveActionOtp("owner@example.test", scope, account, "123456");
        verify(redis).execute(any(), eq(List.of("test:SENSITIVE_ACTION:" + scope + ":owner@example.test",
                "test:attempt:SENSITIVE_ACTION:" + account + ":owner@example.test")), eq("123456"), eq("5"), eq("300"));
    }
    @Test void malformedScopesAndNewlineTargetsFailBeforeMailOrRedis() {
        assertThatThrownBy(() -> service.sendSensitiveActionOtp("owner@example.test", "bad", account, "EMAIL_CHANGE", "target@example.test"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> service.sendSensitiveActionOtp("owner@example.test", scope, account, "EMAIL_CHANGE", "target@example.test\nInjected"))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(redis, mail);
    }
}
