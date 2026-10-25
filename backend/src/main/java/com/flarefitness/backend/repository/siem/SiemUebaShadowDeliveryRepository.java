package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemUebaShadowDelivery;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemUebaShadowDeliveryRepository extends JpaRepository<SiemUebaShadowDelivery, String> {
    List<SiemUebaShadowDelivery> findByRunIdAndAcknowledgedFalseOrderByCreatedAtAscIdAsc(String runId, Pageable pageable);
    long countByRunIdAndAcknowledgedTrue(String runId);
}
