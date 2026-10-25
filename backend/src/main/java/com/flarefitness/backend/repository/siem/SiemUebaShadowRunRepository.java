package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemUebaShadowRun;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SiemUebaShadowRunRepository extends JpaRepository<SiemUebaShadowRun, String> {
    Page<SiemUebaShadowRun> findAllByOrderByCreatedAtDesc(Pageable pageable);
    List<SiemUebaShadowRun> findByStatusInOrderByCreatedAtAsc(Collection<String> statuses, Pageable pageable);
    boolean existsByModelVersionAndStatusIn(String modelVersion, Collection<String> statuses);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from SiemUebaShadowRun r where r.id = :id")
    Optional<SiemUebaShadowRun> locked(@Param("id") String id);
}
