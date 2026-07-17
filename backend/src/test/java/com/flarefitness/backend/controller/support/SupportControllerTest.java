package com.flarefitness.backend.controller.support;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.support.SupportMessageRequest;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.support.SupportChatService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class SupportControllerTest {

    @Mock
    private SupportChatService supportChatService;
    @Mock
    private IpAddressResolver ipAddressResolver;
    @Mock
    private IpRateLimitService ipRateLimitService;
    @Mock
    private HttpServletRequest servletRequest;

    @Test
    void customerMessageIsLimitedByBothIpAndAuthenticatedActor() {
        SupportController controller = new SupportController(
                supportChatService, ipAddressResolver, ipRateLimitService, 20);
        Authentication authentication = new UsernamePasswordAuthenticationToken("customer", null);
        SupportMessageRequest request = new SupportMessageRequest("Can tu van san pham");
        when(ipAddressResolver.resolve(servletRequest)).thenReturn("203.0.113.20");

        controller.appendCustomerMessage(authentication, request, servletRequest);

        verify(ipRateLimitService).assertWithinLimit(
                "support-message-ip", "203.0.113.20", 20, Duration.ofMinutes(1));
        verify(ipRateLimitService).assertWithinLimit(
                "support-message-actor-scope", "customer:customer", 20, Duration.ofMinutes(1));
        verify(supportChatService).appendCustomerMessage(authentication, request);
    }

    @Test
    void staffMessageAlsoUsesThreadScope() {
        SupportController controller = new SupportController(
                supportChatService, ipAddressResolver, ipRateLimitService, 20);
        Authentication authentication = new UsernamePasswordAuthenticationToken("staff", null);
        SupportMessageRequest request = new SupportMessageRequest("Da phan hoi");
        when(ipAddressResolver.resolve(servletRequest)).thenReturn("203.0.113.21");

        controller.appendWorkspaceMessage(authentication, "thread-1", request, servletRequest);

        verify(ipRateLimitService).assertWithinLimit(
                "support-message-actor-scope", "staff:thread:thread-1", 20, Duration.ofMinutes(1));
        verify(supportChatService).appendWorkspaceMessage(authentication, "thread-1", request);
    }
}
