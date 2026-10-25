package com.flarefitness.backend.service;

import com.flarefitness.backend.entity.User;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Independent action authorization. An ML score never disables this policy. */
@Component
public class SensitiveActionPolicy {
    public static final String ID = "email-otp-every-sensitive-action-v1";
    private final boolean enabled;
    private final Set<String> accountIds;

    public SensitiveActionPolicy(
            @Value("${app.sensitive-action-confirmation.enabled:false}") boolean enabled,
            @Value("${app.sensitive-action-confirmation.account-allowlist:}") String accountAllowlist) {
        this.enabled = enabled;
        this.accountIds = Arrays.stream(accountAllowlist.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
        if (accountIds.stream().anyMatch(s -> !s.matches("[A-Za-z0-9_-]{1,64}"))
                || enabled && accountIds.isEmpty()) {
            throw new IllegalArgumentException("Sensitive action policy requires an explicit account ID allowlist.");
        }
    }

    public boolean requiresConfirmation(User user) {
        return enabled && user != null && accountIds.contains(user.getId());
    }
}
