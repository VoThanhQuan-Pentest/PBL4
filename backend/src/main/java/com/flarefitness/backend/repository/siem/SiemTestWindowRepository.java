package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemTestWindow;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SiemTestWindowRepository extends JpaRepository<SiemTestWindow, String> {
    List<SiemTestWindow> findTop100ByOrderByStartsAtDesc();
    List<SiemTestWindow> findByActiveTrueAndStartsAtLessThanEqualAndEndsAtGreaterThanEqual(
            LocalDateTime eventTimeUpperBound,
            LocalDateTime eventTimeLowerBound);
}
