package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemResponseAction;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemResponseActionRepository extends JpaRepository<SiemResponseAction, String> {
    Optional<SiemResponseAction> findByRequestId(String requestId);
}
