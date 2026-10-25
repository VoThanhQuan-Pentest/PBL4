package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class SecurityEventServiceTest {
    @Test
    void usesServerActorAndAllowlistedRouteRatherThanRawRequestData() {
        SiemSecurityEventRepository repository = Mockito.mock(SiemSecurityEventRepository.class);
        SecurityEventService service = new SecurityEventService(repository, true);

        service.recordCustomerRequest("customer-1", "127.0.0.1", "GET",
                "/api/admin/users", 403, "<script>Chrome/123 fake</script>");

        ArgumentCaptor<SiemSecurityEvent> saved = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getActorUserId()).isEqualTo("customer-1");
        assertThat(saved.getValue().getTargetUserId()).isNull();
        assertThat(saved.getValue().getRouteGroup()).isEqualTo("admin");
        assertThat(saved.getValue().getHttpStatus()).isEqualTo(403);
        assertThat(saved.getValue().getUserAgentFamily()).isEqualTo("CHROMIUM");
    }

    @Test
    void routeNormalizerRejectsQueryAndFragmentRatherThanPersistingThem() {
        assertThatThrownBy(() -> SecurityEventNormalizer.routeGroup("/api/admin/users?token=do-not-store"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SecurityEventNormalizer.routeGroup("/api/admin/users#fragment"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void failedLoginMarksKnownTargetWithoutAttributingActor() {
        SiemSecurityEventRepository repository = Mockito.mock(SiemSecurityEventRepository.class);
        SecurityEventService service = new SecurityEventService(repository, true);

        service.recordAuth("LOGIN", "FAILURE", null, "target-1", "127.0.0.1", "Mozilla Firefox/145.0");

        ArgumentCaptor<SiemSecurityEvent> saved = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getActorUserId()).isNull();
        assertThat(saved.getValue().getTargetUserId()).isEqualTo("target-1");
        assertThat(saved.getValue().getUserAgentFamily()).isEqualTo("FIREFOX");
    }

    @Test
    void disabledFeatureDoesNotPersistEvents() {
        SiemSecurityEventRepository repository = Mockito.mock(SiemSecurityEventRepository.class);
        new SecurityEventService(repository, false).recordCustomerRequest("user-1", "127.0.0.1",
                "GET", "/api/orders/me", 200, null);
        verifyNoInteractions(repository);
    }
}
