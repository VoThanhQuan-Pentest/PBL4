package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.flarefitness.backend.dto.auth.LoginOtpRequest;
import com.flarefitness.backend.dto.auth.LoginRequest;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class LoginOtpAuditTest {
    @Mock AuthService auth;
    @Mock UserRepository users;
    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> values;
    @Mock PasswordEncoder encoder;
    @Mock JavaMailSender mail;
    @Mock AuditLogService audit;
    LoginOtpService service;

    @BeforeEach void setup() {
        service = new LoginOtpService(auth, users, redis, encoder, mail,
                "owned-test:", "noreply@example.test", true, audit);
    }

    @Test void missingProofIsAuditedWithoutGuessingAccountOrExpiry() {
        when(redis.opsForValue()).thenReturn(values);
        assertThatThrownBy(() -> service.verify(request(), "127.0.0.1", "owned-agent"))
                .isInstanceOf(UnauthorizedException.class);
        verify(audit).failure("AUTH_LOGIN_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        verifyNoMoreInteractions(audit);
        verifyNoInteractions(auth, users, encoder, mail);
    }

    @Test void passwordRejectionDoesNotClaimAnIssuedOrVerifiedEmailFactor() {
        LoginRequest request = new LoginRequest("owned-user", "owned-password");
        when(auth.authenticateForLogin(request, "127.0.0.1", "owned-agent"))
                .thenThrow(new UnauthorizedException("owned rejection"));
        assertThatThrownBy(() -> service.begin(request, "127.0.0.1", "owned-agent"))
                .isInstanceOf(UnauthorizedException.class);
        verify(audit).failure("AUTH_LOGIN_OTP_CHALLENGE_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        verifyNoMoreInteractions(audit);
        verifyNoInteractions(users, redis, encoder, mail);
    }

    @Test void auditFailureCannotReplaceTheAuthenticationRejection() {
        when(redis.opsForValue()).thenReturn(values);
        doThrow(new IllegalStateException("owned unavailable sink"))
                .when(audit).failure("AUTH_LOGIN_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        assertThatThrownBy(() -> service.verify(request(), "127.0.0.1", "owned-agent"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("OTP dang nhap");
        verifyNoInteractions(auth, users, encoder, mail);
    }

    private LoginOtpRequest request() {
        return new LoginOtpRequest("f47ac10b-58cc-4372-a567-0e02b2c3d479", "000001");
    }
}
