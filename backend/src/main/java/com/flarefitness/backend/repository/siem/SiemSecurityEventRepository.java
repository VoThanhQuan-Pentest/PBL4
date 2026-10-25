package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;

public interface SiemSecurityEventRepository extends JpaRepository<SiemSecurityEvent, String> {
    @Query("""
            select e from SiemSecurityEvent e where e.actorUserId=:account and e.sessionPseudonym=:session
            and e.eventType='AUTH' and e.action='LOGIN' and e.outcome='SUCCESS'
            and e.eventTimestamp>=:from and e.eventTimestamp<:to order by e.eventTimestamp desc
            """)
    List<SiemSecurityEvent> findSessionLogin(@Param("account") String account, @Param("session") String session,
            @Param("from") LocalDateTime from, @Param("to") LocalDateTime to, Pageable pageable);
    long countByAggregatedAtIsNull();
    long countByExportedAtIsNull();
    List<SiemSecurityEvent> findByExportedAtIsNullOrderByCreatedAtAsc(Pageable pageable);

    List<SiemSecurityEvent> findByAggregatedAtIsNullAndEventTimestampBeforeOrderByEventTimestampAsc(
            LocalDateTime before, Pageable pageable);

    @Query("""
            select e from SiemSecurityEvent e
            where e.eventTimestamp >= :from and e.eventTimestamp < :to
              and e.eventType <> 'AUTH_INVESTIGATION'
              and (e.actorUserId = :accountId
                or (e.actorUserId is null and e.targetUserId = :accountId))
            order by e.eventTimestamp asc, e.id asc
            """)
    Page<SiemSecurityEvent> findAccountWindow(@Param("accountId") String accountId,
                                               @Param("from") LocalDateTime from,
                                               @Param("to") LocalDateTime to,
                                               Pageable pageable);

    @Query("""
            select e from SiemSecurityEvent e
            where e.eventTimestamp >= :from and e.eventTimestamp < :to
              and (e.actorUserId = :accountId
                or (e.actorUserId is null and e.targetUserId = :accountId))
            order by e.eventTimestamp desc, e.id desc
            """)
    Page<SiemSecurityEvent> findAccountEvidence(@Param("accountId") String accountId,
                                                 @Param("from") LocalDateTime from,
                                                 @Param("to") LocalDateTime to,
                                                 Pageable pageable);

    @Modifying
    @Query(value = """
            DELETE FROM siem_security_events
            WHERE event_timestamp < :cutoff
              AND exported_at IS NOT NULL AND aggregated_at IS NOT NULL
            LIMIT 1000
            """, nativeQuery = true)
    int purgeProcessedBefore(@Param("cutoff") LocalDateTime cutoff);

}
