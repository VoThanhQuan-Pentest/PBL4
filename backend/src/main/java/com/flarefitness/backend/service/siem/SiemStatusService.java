package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.SiemIngestionCheckpoint;
import com.flarefitness.backend.repository.siem.SiemIngestionCheckpointRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SiemStatusService {
    public static final String ALERT_STREAM = "security-alerts";
    private final SiemIngestionCheckpointRepository checkpointRepository;
    private final SiemElasticGateway elasticGateway;

    public SiemStatusService(
            SiemIngestionCheckpointRepository checkpointRepository,
            SiemElasticGateway elasticGateway
    ) {
        this.checkpointRepository = checkpointRepository;
        this.elasticGateway = elasticGateway;
    }

    @Transactional(readOnly = true)
    public SiemDtos.Status status() {
        SiemIngestionCheckpoint checkpoint = checkpointRepository.findByStreamName(ALERT_STREAM).orElse(null);
        return new SiemDtos.Status(
                elasticGateway.isEnabled(),
                elasticGateway.isAvailable(),
                checkpoint == null ? null : checkpoint.getLastSuccessAt(),
                checkpoint == null ? null : checkpoint.getLastErrorAt(),
                checkpoint == null ? null : checkpoint.getLastError());
    }
}
