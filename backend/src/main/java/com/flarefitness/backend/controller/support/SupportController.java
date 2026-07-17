package com.flarefitness.backend.controller.support;

import com.flarefitness.backend.dto.support.SupportMessageRequest;
import com.flarefitness.backend.dto.support.SupportMessageResponse;
import com.flarefitness.backend.dto.support.SupportThreadResponse;
import com.flarefitness.backend.dto.support.SupportThreadStatusRequest;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.support.SupportChatService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/support")
public class SupportController {

    private final SupportChatService supportChatService;
    private final IpAddressResolver ipAddressResolver;
    private final IpRateLimitService ipRateLimitService;
    private final int maxMessagesPerMinute;

    public SupportController(
            SupportChatService supportChatService,
            IpAddressResolver ipAddressResolver,
            IpRateLimitService ipRateLimitService,
            @org.springframework.beans.factory.annotation.Value("${app.security.support.max-messages-per-minute:20}") int maxMessagesPerMinute
    ) {
        this.supportChatService = supportChatService;
        this.ipAddressResolver = ipAddressResolver;
        this.ipRateLimitService = ipRateLimitService;
        this.maxMessagesPerMinute = maxMessagesPerMinute;
    }

    @GetMapping("/me")
    public ResponseEntity<SupportThreadResponse> getCurrentCustomerThread(
            Authentication authentication,
            @RequestParam(defaultValue = "false") boolean createIfMissing
    ) {
        SupportThreadResponse response = supportChatService.getCurrentCustomerThread(authentication, createIfMissing);
        return response == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(response);
    }

    @PostMapping("/me/messages")
    public ResponseEntity<SupportThreadResponse> appendCustomerMessage(
            Authentication authentication,
            @Valid @RequestBody SupportMessageRequest request,
            HttpServletRequest httpServletRequest
    ) {
        assertMessageRateLimit(authentication, httpServletRequest, "customer");
        return ResponseEntity.ok(supportChatService.appendCustomerMessage(authentication, request));
    }

    @GetMapping("/me/messages")
    public ResponseEntity<PageResponse<SupportMessageResponse>> getCurrentCustomerMessages(
            Authentication authentication,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "50") Integer size
    ) {
        return ResponseEntity.ok(supportChatService.getCurrentCustomerMessages(authentication, page, size));
    }

    @GetMapping("/threads")
    public ResponseEntity<List<SupportThreadResponse>> getThreads(Authentication authentication) {
        return ResponseEntity.ok(supportChatService.getThreadsForWorkspace(authentication));
    }

    @GetMapping("/threads/page")
    public ResponseEntity<PageResponse<SupportThreadResponse>> getThreadsPage(
            Authentication authentication,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "50") Integer size
    ) {
        return ResponseEntity.ok(supportChatService.getThreadsForWorkspacePage(authentication, page, size));
    }

    @GetMapping("/threads/{threadId}/messages")
    public ResponseEntity<PageResponse<SupportMessageResponse>> getThreadMessages(
            Authentication authentication,
            @PathVariable String threadId,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "50") Integer size
    ) {
        return ResponseEntity.ok(supportChatService.getWorkspaceMessages(authentication, threadId, page, size));
    }

    @PostMapping("/threads/{threadId}/messages")
    public ResponseEntity<SupportThreadResponse> appendWorkspaceMessage(
            Authentication authentication,
            @PathVariable String threadId,
            @Valid @RequestBody SupportMessageRequest request,
            HttpServletRequest httpServletRequest
    ) {
        assertMessageRateLimit(authentication, httpServletRequest, "thread:" + threadId);
        return ResponseEntity.ok(supportChatService.appendWorkspaceMessage(authentication, threadId, request));
    }

    @PutMapping("/threads/{threadId}/status")
    public ResponseEntity<SupportThreadResponse> updateThreadStatus(
            Authentication authentication,
            @PathVariable String threadId,
            @Valid @RequestBody SupportThreadStatusRequest request
    ) {
        return ResponseEntity.ok(supportChatService.updateThreadStatus(authentication, threadId, request));
    }

    private void assertMessageRateLimit(
            Authentication authentication,
            HttpServletRequest httpServletRequest,
            String scope) {
        String ipAddress = ipAddressResolver.resolve(httpServletRequest);
        String actor = authentication == null ? "anonymous" : String.valueOf(authentication.getName());
        ipRateLimitService.assertWithinLimit(
                "support-message-ip",
                ipAddress,
                maxMessagesPerMinute,
                Duration.ofMinutes(1));
        ipRateLimitService.assertWithinLimit(
                "support-message-actor-scope",
                actor + ":" + scope,
                maxMessagesPerMinute,
                Duration.ofMinutes(1));
    }
}
