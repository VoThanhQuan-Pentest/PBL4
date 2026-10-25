package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemAlertRef;
import java.util.List;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemAlertRefRepository extends JpaRepository<SiemAlertRef, String> {
    boolean existsByElasticAlertId(String elasticAlertId);
    Optional<SiemAlertRef> findByElasticAlertId(String elasticAlertId);
    List<SiemAlertRef> findTop100ByIncidentIdOrderByEventTimestampDesc(String incidentId);
    long countByIncidentId(String incidentId);
    List<SiemAlertRef> findBySourceIpAndServiceIdAndEventTimestampBetween(
            String sourceIp, String serviceId, LocalDateTime from, LocalDateTime to);
}
