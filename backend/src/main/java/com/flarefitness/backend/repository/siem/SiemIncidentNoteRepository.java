package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemIncidentNote;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemIncidentNoteRepository extends JpaRepository<SiemIncidentNote, String> {
    List<SiemIncidentNote> findTop100ByIncidentIdOrderByCreatedAtDesc(String incidentId);
}
