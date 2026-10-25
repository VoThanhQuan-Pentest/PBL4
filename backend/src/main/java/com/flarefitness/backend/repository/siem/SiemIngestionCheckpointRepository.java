package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemIngestionCheckpoint;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemIngestionCheckpointRepository extends JpaRepository<SiemIngestionCheckpoint, String> {
    Optional<SiemIngestionCheckpoint> findByStreamName(String streamName);
}
