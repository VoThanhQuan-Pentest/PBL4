package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.sync.SyncStateResponse;
import com.flarefitness.backend.dto.voucher.VoucherAssignmentRequest;
import com.flarefitness.backend.entity.sync.SyncState;
import com.flarefitness.backend.service.VoucherPricingService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Administrative voucher-entitlement operations; client sync state is read-only. */
@RestController
@RequestMapping("/api/admin/vouchers")
@PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_STAFF')")
public class VoucherAdminController {

    private final VoucherPricingService voucherPricingService;

    public VoucherAdminController(VoucherPricingService voucherPricingService) {
        this.voucherPricingService = voucherPricingService;
    }

    @PostMapping("/assignments")
    public ResponseEntity<SyncStateResponse> grantVoucher(@Valid @RequestBody VoucherAssignmentRequest request) {
        return ResponseEntity.ok(toResponse(voucherPricingService.grantVoucherToUser(
                request.userId(), request.voucherCode(), request.quantity())));
    }

    /** Returns the current server-authoritative entitlement for one customer. */
    @GetMapping("/assignments/{userId}")
    public ResponseEntity<SyncStateResponse> getVoucherAssignments(@PathVariable String userId) {
        return ResponseEntity.ok(toResponse(voucherPricingService.getAssignmentsForUser(userId)));
    }

    @DeleteMapping("/assignments/{userId}/{voucherCode}")
    public ResponseEntity<SyncStateResponse> revokeVoucher(
            @PathVariable String userId,
            @PathVariable String voucherCode
    ) {
        return ResponseEntity.ok(toResponse(voucherPricingService.revokeVoucherForUser(userId, voucherCode)));
    }

    private SyncStateResponse toResponse(SyncState state) {
        return new SyncStateResponse(
                state.getScope(), state.getOwnerId(), state.getKeyName(), state.getPayload(), state.getUpdatedAt());
    }
}
