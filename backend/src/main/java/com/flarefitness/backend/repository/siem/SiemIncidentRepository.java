package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.SiemIncident;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface SiemIncidentRepository
        extends JpaRepository<SiemIncident, String>, JpaSpecificationExecutor<SiemIncident> {
    Optional<SiemIncident> findByGroupingKey(String groupingKey);
    long countByStatus(IncidentStatus status);
    long countBySeverity(IncidentSeverity severity);
    long countByClassification(IncidentClassification classification);
    long countByTargetUserIdAndOrigin(String targetUserId, IncidentOrigin origin);
    long countByLastSeenGreaterThanEqual(LocalDateTime since);
    Page<SiemIncident> findAllByOrderByLastSeenDesc(Pageable pageable);
}
