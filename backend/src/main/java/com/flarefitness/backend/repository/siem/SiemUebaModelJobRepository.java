package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemUebaModelJob;
import java.util.Optional;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SiemUebaModelJobRepository extends JpaRepository<SiemUebaModelJob, String> {
    Optional<SiemUebaModelJob> findByModelVersion(String modelVersion);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select j from SiemUebaModelJob j where j.modelVersion = :version")
    Optional<SiemUebaModelJob> lockedByModelVersion(@Param("version") String version);
    List<SiemUebaModelJob> findByStatus(String status);
    List<SiemUebaModelJob> findByActivationStatusInOrderByUpdatedAtAsc(List<String> statuses, Pageable pageable);
    Page<SiemUebaModelJob> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
