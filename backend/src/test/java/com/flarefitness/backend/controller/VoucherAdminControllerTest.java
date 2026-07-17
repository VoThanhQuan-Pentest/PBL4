package com.flarefitness.backend.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.sync.SyncStateResponse;
import com.flarefitness.backend.entity.sync.SyncState;
import com.flarefitness.backend.service.VoucherPricingService;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
class VoucherAdminControllerTest {

    @Mock
    private VoucherPricingService voucherPricingService;

    @Test
    void returnsTheSelectedCustomersServerAuthoritativeEntitlement() {
        SyncState state = new SyncState();
        state.setScope("USER");
        state.setOwnerId("customer-1");
        state.setKeyName("voucher-assignments");
        state.setPayload("{\"codes\":[\"HOTDEAL10\"]}");
        state.setUpdatedAt(LocalDateTime.of(2026, 7, 14, 12, 0));
        when(voucherPricingService.getAssignmentsForUser("customer-1")).thenReturn(state);

        VoucherAdminController controller = new VoucherAdminController(voucherPricingService);
        ResponseEntity<SyncStateResponse> response = controller.getVoucherAssignments("customer-1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo(new SyncStateResponse(
                "USER", "customer-1", "voucher-assignments", "{\"codes\":[\"HOTDEAL10\"]}",
                LocalDateTime.of(2026, 7, 14, 12, 0)));
        verify(voucherPricingService).getAssignmentsForUser("customer-1");
    }
}
