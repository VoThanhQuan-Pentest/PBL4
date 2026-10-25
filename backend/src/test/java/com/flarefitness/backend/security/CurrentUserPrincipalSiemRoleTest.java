package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CurrentUserPrincipalSiemRoleTest {
    @Test
    void mapsLegacyAnalystToL1AndExplicitL2ToHigherTier() {
        assertThat(CurrentUserPrincipal.toAuthority("Security analyst")).isEqualTo("ROLE_SOC_L1");
        assertThat(CurrentUserPrincipal.toAuthority("Chuyen vien an ninh")).isEqualTo("ROLE_SOC_L1");
        assertThat(CurrentUserPrincipal.toAuthority("SOC L1")).isEqualTo("ROLE_SOC_L1");
        assertThat(CurrentUserPrincipal.toAuthority("SOC L2")).isEqualTo("ROLE_SOC_L2");
        assertThat(CurrentUserPrincipal.toAuthority("Nhan vien")).isEqualTo("ROLE_STAFF");
        assertThat(CurrentUserPrincipal.toAuthority("Khach hang")).isEqualTo("ROLE_CUSTOMER");
    }
}
