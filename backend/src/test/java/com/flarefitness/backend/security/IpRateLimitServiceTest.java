package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import com.flarefitness.backend.exception.TooManyRequestsException;

@ExtendWith(MockitoExtension.class)
class IpRateLimitServiceTest {

    @Mock private StringRedisTemplate redisTemplate;

    private IpRateLimitService rateLimitService;

    @BeforeEach
    void setUp() {
        rateLimitService = new IpRateLimitService(redisTemplate, "auth:login-attempt:", 5, 5, 5, 20, 20, 80);
    }

    @Test
    void loginRateLimitAtomicallyReservesSeparateOpaqueIpAndAccountBuckets() {
        doReturn(1L).when(redisTemplate).execute(any(), anyList(), any(), any(), any());

        rateLimitService.assertLoginAllowed("203.0.113.9", "Alice");

        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redisTemplate).execute(any(), keys.capture(), any(), any(), any());
        assertThat(keys.getValue()).hasSize(2).allSatisfy(key -> assertThat(key)
                .doesNotContain("203.0.113.9")
                .doesNotContain("Alice"));
        assertThat(keys.getValue())
                .anySatisfy(key -> assertThat(key).contains(":ip:"))
                .anySatisfy(key -> assertThat(key).contains(":account:"));
    }

    @Test
    void successfulLoginOnlyClearsTheAccountBucket() {
        rateLimitService.recordSuccessfulLogin("203.0.113.9", "Alice");

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(redisTemplate).delete(key.capture());
        assertThat(key.getValue())
                .contains(":account:")
                .doesNotContain("203.0.113.9")
                .doesNotContain("Alice");
    }

    @Test
    void atomicReservationBlocksTheRequestThatExceedsTheLimit() {
        doReturn(0L).when(redisTemplate).execute(any(), anyList(), any(), any(), any());

        assertThatThrownBy(() -> rateLimitService.assertLoginAllowed("203.0.113.9", "Alice"))
                .isInstanceOf(TooManyRequestsException.class);
    }
}
