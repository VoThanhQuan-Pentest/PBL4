package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.SensitiveActionConfirmation;
import jakarta.persistence.LockModeType;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SensitiveActionConfirmationRepository extends JpaRepository<SensitiveActionConfirmation, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from SensitiveActionConfirmation a where a.id = :id")
    Optional<SensitiveActionConfirmation> findForUpdate(@Param("id") String id);

    long countByUserIdAndStateAndExpiresAtAfter(String userId, String state, LocalDateTime now);

    @Modifying
    @Query("update SensitiveActionConfirmation a set a.passwordHash = null, a.profileName = null, "
            + "a.targetEmail = null, a.phone = null, a.state = 'EXPIRED' "
            + "where a.state = 'PENDING' and a.expiresAt <= :now")
    int expireAndScrub(@Param("now") LocalDateTime now);

    @Modifying
    @Query("delete from SensitiveActionConfirmation a where a.expiresAt < :before")
    int deleteOld(@Param("before") LocalDateTime before);
}
