package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.sync.SyncStateRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceGoneException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.sync.SyncStateRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class SyncStateServiceTest {

    @Mock
    private SyncStateRepository syncStateRepository;
    @Mock
    private VoucherPricingService voucherPricingService;

    private SyncStateService syncStateService;

    @BeforeEach
    void setUp() {
        syncStateService = new SyncStateService(syncStateRepository, voucherPricingService, new ObjectMapper());
    }

    @Test
    void authenticatedRoleDenialsAreForbiddenWhileMissingAuthenticationIsUnauthorized() {
        Authentication customerAuthentication = authentication(user("customer-1", "customer"));
        Authentication staffAuthentication = authentication(user("staff-1", "staff"));
        SyncStateRequest request = new SyncStateRequest("{}");

        assertThatThrownBy(() -> syncStateService.saveAppState(
                "category-registry", request, customerAuthentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("khong co quyen");

        assertThatThrownBy(() -> syncStateService.saveCurrentUserState("cart", request, staffAuthentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("chi danh cho khach hang");

        assertThatThrownBy(() -> syncStateService.getCurrentUserState("cart", null))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Phien dang nhap");
    }

    @Test
    void retiredManagedReviewsKeyIsGoneWithoutRepositoryAccess() {
        Authentication staffAuthentication = authentication(user("staff-1", "staff"));

        assertThatThrownBy(() -> syncStateService.getAppState("managed-reviews"))
                .isInstanceOf(ResourceGoneException.class);
        assertThatThrownBy(() -> syncStateService.saveAppState(
                "managed-reviews", new SyncStateRequest("[]"), staffAuthentication))
                .isInstanceOf(ResourceGoneException.class);

        verifyNoInteractions(syncStateRepository, voucherPricingService);
    }

    @Test
    void unknownAppKeysRemainBadRequests() {
        assertThatThrownBy(() -> syncStateService.getAppState("unknown-key"))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(syncStateRepository, voucherPricingService);
    }

    private User user(String id, String role) {
        User user = new User();
        user.setId(id);
        user.setUsername(id);
        user.setPassword("password");
        user.setRole(role);
        user.setStatus("ACTIVE");
        user.setDeleted(false);
        return user;
    }

    private Authentication authentication(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
