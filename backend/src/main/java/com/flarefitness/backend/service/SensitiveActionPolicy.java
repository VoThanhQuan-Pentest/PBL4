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
    public static final String EMAIL_CHANGE_ID = "password-and-current-email-otp-v2";
    private final boolean enabled;
    private final Set<String> accountIds;
    private final boolean loginOtpEnabled;

    public SensitiveActionPolicy(boolean enabled, String accountAllowlist) {
        this(enabled, accountAllowlist, false);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SensitiveActionPolicy(
            @Value("${app.sensitive-action-confirmation.enabled:false}") boolean enabled,
            @Value("${app.sensitive-action-confirmation.account-allowlist:}") String accountAllowlist,
            @Value("${app.security.login-otp-enabled:false}") boolean loginOtpEnabled) {
        this.enabled = enabled;
        this.loginOtpEnabled = loginOtpEnabled;
        this.accountIds = Arrays.stream(accountAllowlist.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
        if (accountIds.stream().anyMatch(s -> !s.matches("[A-Za-z0-9_-]{1,64}"))
                || enabled && accountIds.isEmpty()) {
            throw new IllegalArgumentException("Sensitive action policy requires an explicit account ID allowlist.");
        }
    }

    public boolean requiresConfirmation(User user) {
        return user != null && requiresExperimentalConfirmation(user.getId());
    }

    boolean requiresExperimentalConfirmation(String accountId) {
        return enabled && accountId != null && accountIds.contains(accountId);
    }

    /** Rebinding an enrolled login factor is independent of the experimental cohort. */
    public boolean requiresEmailChangeConfirmation(User user) {
        return user != null && (loginOtpEnabled || requiresConfirmation(user));
    }

    public static String policyId(String operation) {
        return "EMAIL_CHANGE".equals(operation) ? EMAIL_CHANGE_ID : ID;
    }
}
