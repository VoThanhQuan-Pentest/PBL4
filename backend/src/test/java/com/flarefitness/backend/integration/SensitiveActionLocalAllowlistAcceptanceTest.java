package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.ConfigurableEnvironment;

/** Post-gate acceptance: policy comes from local runtime env, not test properties. */
@EnabledIfEnvironmentVariable(named="FLARE_LOCAL_OTP_ACCEPTANCE", matches="true")
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, properties={
    "server.address=127.0.0.1","siem.enabled=false","siem.ueba.enabled=false","siem.prevention.enabled=false",
    "siem.security-events.enabled=false","management.health.mail.enabled=false","logging.level.AUDIT=OFF"})
class SensitiveActionLocalAllowlistAcceptanceTest extends SensitiveActionConfirmationIntegrationTest {
    @Autowired ConfigurableEnvironment environment;

    @Test @Timeout(120)
    void onlyExplicitLocalAccountIdsReceiveTheRuntimePolicy() throws Exception {
        var inline=environment.getPropertySources().get("Inlined Test Properties");
        assertThat(inline==null || inline.getProperty("app.sensitive-action-confirmation.enabled")==null).isTrue();
        assertThat("true".equals(System.getenv("APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"))).isTrue();
        captureMail();
        var included=fixture("confirmation-password-runtime");
        var excluded=fixture("confirmation-unlisted-runtime");
        try(var owner=new Client();var other=new Client()) {
            login(owner,included);login(other,excluded);
            var yes=body(send(owner,"GET","/api/profile/action-confirmations/policy",null,200));
            var no=body(send(other,"GET","/api/profile/action-confirmations/policy",null,200));
            assertThat(yes.path("required").asBoolean()).isTrue();
            assertThat(no.path("required").asBoolean()).isFalse();
            var request=Map.of("current_password",CURRENT,"new_password",REPLACEMENT,"confirm_password",REPLACEMENT);
            send(owner,"PUT","/api/profile/password",request,409);
            assertThat(users.findById(included.getId()).orElseThrow().getPassword()).isEqualTo(included.getPassword());
            send(other,"PUT","/api/profile/password",request,204);
            assertThat(encoder.matches(REPLACEMENT,users.findById(excluded.getId()).orElseThrow().getPassword())).isTrue();
        }
    }
}
