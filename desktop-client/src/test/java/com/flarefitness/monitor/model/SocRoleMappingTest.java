package com.flarefitness.monitor.model;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class SocRoleMappingTest {
    private String role(String value){return SiemModels.socRole(new SiemModels.User("id","user",value,null,null,null));}
    @Test void recognizesServerRoleAliasesIncludingVietnameseWithoutGrantingUnknownRoles(){
        assertEquals("ADMIN",role("Quản trị viên"));assertEquals("ADMIN",role("Quan tri vien"));assertEquals("ADMIN",role("Admin"));
        assertEquals("L1",role("Chuyên viên bảo mật"));assertEquals("L1",role("Security analyst"));assertEquals("L1",role("SOC L1"));
        assertEquals("L2",role("SOC L2"));assertEquals("L2",role("ROLE_SOC_L2"));
        assertEquals("OTHER",role("Admin assistant"));assertEquals("OTHER",role("customer"));assertEquals("OTHER",role("Nhân viên"));assertEquals("OTHER",SiemModels.socRole(null));
    }
}
