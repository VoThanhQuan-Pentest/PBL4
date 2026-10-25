package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.profile.ActionConfirmationDtos;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.SensitiveActionConfirmationService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/profile/action-confirmations")
public class ActionConfirmationController {
    private final SensitiveActionConfirmationService confirmations;
    private final IpAddressResolver addresses;
    public ActionConfirmationController(SensitiveActionConfirmationService confirmations, IpAddressResolver addresses) {
        this.confirmations = confirmations; this.addresses = addresses;
    }
    @GetMapping("/policy")
    public ActionConfirmationDtos.Policy policy(Authentication authentication) {
        return confirmations.status(authentication.getName());
    }
    @PostMapping
    public ActionConfirmationDtos.Challenge prepare(Authentication authentication, HttpServletRequest request,
            @Valid @RequestBody ActionConfirmationDtos.PrepareRequest body) {
        return confirmations.prepare(actor(authentication, request), body, addresses.resolve(request));
    }
    @PostMapping("/{id}/execute")
    public ActionConfirmationDtos.Executed execute(Authentication authentication, HttpServletRequest request,
            @PathVariable String id, @Valid @RequestBody ActionConfirmationDtos.ExecuteRequest body) {
        return confirmations.execute(actor(authentication, request), id, body, addresses.resolve(request));
    }
    private SensitiveActionConfirmationService.Actor actor(Authentication authentication, HttpServletRequest request) {
        Object metadata = request.getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE);
        if (!(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)
                || !(metadata instanceof UebaSessionTelemetry session)) return null;
        var user = principal.getUser();
        return new SensitiveActionConfirmationService.Actor(authentication.getName(), user.getId(),
                user.getAuthVersion() == null ? 0L : user.getAuthVersion(), session);
    }
}
