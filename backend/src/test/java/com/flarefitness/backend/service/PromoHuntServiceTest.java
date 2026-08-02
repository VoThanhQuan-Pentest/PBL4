package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.promo.PromoHuntCampaignRepository;
import com.flarefitness.backend.repository.promo.PromoHuntClaimRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class PromoHuntServiceTest {

    @Mock
    private PromoHuntCampaignRepository campaignRepository;
    @Mock
    private PromoHuntClaimRepository claimRepository;
    @Mock
    private VoucherPricingService voucherPricingService;

    private PromoHuntService promoHuntService;

    @BeforeEach
    void setUp() {
        promoHuntService = new PromoHuntService(campaignRepository, claimRepository, voucherPricingService);
    }

    @Test
    void authenticatedStaffClaimIsForbiddenWhileMissingAuthenticationIsUnauthorized() {
        User staff = new User();
        staff.setId("staff-1");
        staff.setUsername("staff");
        staff.setPassword("password");
        staff.setRole("staff");
        staff.setStatus("ACTIVE");
        CurrentUserPrincipal principal = new CurrentUserPrincipal(staff);
        var authentication = new UsernamePasswordAuthenticationToken(
                principal, null, principal.getAuthorities());

        assertThatThrownBy(() -> promoHuntService.claimCampaign(authentication, "campaign-1"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("nhan vien va quan tri vien");

        assertThatThrownBy(() -> promoHuntService.claimCampaign(null, "campaign-1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("dang nhap");
    }
}
