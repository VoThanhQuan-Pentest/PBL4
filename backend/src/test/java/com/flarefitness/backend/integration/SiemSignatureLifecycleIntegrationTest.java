package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.siem.PreventionDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.siem.SiemPreventionGateway;
import com.flarefitness.backend.service.siem.SiemPreventionService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class SiemSignatureLifecycleIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private SiemPreventionService prevention;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwords;
    @MockBean private SiemPreventionGateway gateway;

    @Test
    void signatureBecomesActiveOnlyAfterPassingTestAndGatewayAcknowledgement() throws Exception {
        Authentication l2 = analyst("SOC L2");
        when(gateway.test(any(), anyList(), any())).thenAnswer(invocation -> {
            String hash = invocation.getArgument(2);
            return new PreventionDtos.TestResult(true, 2, 2, hash);
        });
        PreventionDtos.Signature draft = prevention.create(new PreventionDtos.CreateSignature(
                PreventionDtos.SignatureKind.PATH_EXACT, "GET", null,
                "/.well-known/flare-signature-check", "HIGH", null), l2);
        assertThat(draft.status()).isEqualTo(PreventionDtos.SignatureStatus.DRAFT);

        var tested = prevention.test(draft.id(), draft.version(), new PreventionDtos.TestSignature(List.of(
                new PreventionDtos.TestFixture("GET", "/.well-known/flare-signature-check", null, true),
                new PreventionDtos.TestFixture("GET", "/products/123", null, false))), l2);
        assertThat(tested.passed()).isTrue();
        PreventionDtos.Signature candidate = prevention.revise(draft.id(), draft.version(),
                new PreventionDtos.CreateSignature(PreventionDtos.SignatureKind.PATH_EXACT,
                        "GET", null, "/.well-known/flare-signature-check", "HIGH", null), l2);
        assertThat(candidate.status()).isEqualTo(PreventionDtos.SignatureStatus.DRAFT);
        // Editing after a successful test invalidates the test, even when the submitted values look identical.
        var secondTest = prevention.test(candidate.id(), candidate.version(), new PreventionDtos.TestSignature(List.of(
                new PreventionDtos.TestFixture("GET", "/.well-known/flare-signature-check", null, true),
                new PreventionDtos.TestFixture("GET", "/products/123", null, false))), l2);
        assertThat(secondTest.passed()).isTrue();
        PreventionDtos.Signature testedAgain = jdbcSignature(candidate.id());
        PreventionDtos.Signature publishing = prevention.activate(testedAgain.id(), testedAgain.version(), l2);
        assertThat(publishing.status()).isEqualTo(PreventionDtos.SignatureStatus.PUBLISHING);
        var policy = prevention.activePolicy();
        assertThat(policy.get("version")).isInstanceOf(Number.class);
        long firstPolicyVersion = ((Number) policy.get("version")).longValue();
        String checksum = (String) policy.get("checksum");
        assertThat(policy.get("policy_json").toString()).contains(testedAgain.id());
        prevention.acknowledge(firstPolicyVersion, checksum);
        PreventionDtos.Signature active = jdbcSignature(testedAgain.id());
        assertThat(active.status()).isEqualTo(PreventionDtos.SignatureStatus.ACTIVE);

        PreventionDtos.Signature deactivating = prevention.disable(active.id(), active.version(), l2);
        assertThat(deactivating.status()).isEqualTo(PreventionDtos.SignatureStatus.DEACTIVATING);
        var removalPolicy = prevention.activePolicy();
        assertThat(removalPolicy.get("policy_json").toString()).doesNotContain(active.id());
        prevention.acknowledge(((Number) removalPolicy.get("version")).longValue(),
                (String) removalPolicy.get("checksum"));
        assertThat(jdbcSignature(active.id()).status()).isEqualTo(PreventionDtos.SignatureStatus.DISABLED);
    }

    private PreventionDtos.Signature jdbcSignature(String id) {
        // Reuse the authenticated read API contract through JDBC's persisted row by deserializing the DTO.
        var response = prevention.signatures(0, 100, analyst("SOC L2"));
        return response.content().stream().filter(item -> item.id().equals(id)).findFirst().orElseThrow();
    }

    private Authentication analyst(String role) {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        User user = new User();
        user.setId("prevention-" + suffix);
        user.setUsername("prevention_" + suffix);
        user.setPassword(passwords.encode("Integration#1"));
        user.setRole(role);
        user.setHoTen("Prevention integration analyst");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        users.saveAndFlush(user);
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
