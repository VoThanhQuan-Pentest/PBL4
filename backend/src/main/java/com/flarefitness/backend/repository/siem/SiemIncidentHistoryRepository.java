package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemIncidentHistoryRepository extends JpaRepository<SiemIncidentHistory, String> {
    List<SiemIncidentHistory> findTop100ByIncidentIdOrderByCreatedAtDesc(String incidentId);
    Page<SiemIncidentHistory> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
