package com.flarefitness.backend.repository.siem;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.service.siem.AccountBaselinePolicy;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SiemAccountBehaviorWindowRepository extends JpaRepository<SiemAccountBehaviorWindow, String> {
    long countByScoreStatus(BehaviorScoreStatus status);
    long countByAccountId(String accountId);

    @Query("""
            select w from SiemAccountBehaviorWindow w
            where w.windowEnd >= :from and w.windowEnd <= :to
              and ((:schema = 2 and w.personalFeatureSchemaVersion = 2 and w.personalFeatureVectorJson is not null)
                or (:schema = 3 and w.contextualFeatureSchemaVersion = 3 and w.contextualFeatureVectorJson is not null)
                or (:schema = 4 and w.sessionEndpointFeatureSchemaVersion = 4 and w.sessionEndpointFeatureVectorJson is not null))
              and not exists (select d.id from SiemUebaShadowDelivery d where d.runId = :runId and d.windowId = w.id)
            order by w.windowEnd asc, w.id asc
            """)
    List<SiemAccountBehaviorWindow> findShadowEligible(@Param("runId") String runId,
            @Param("from") LocalDateTime from, @Param("to") LocalDateTime to, @Param("schema") int schema, Pageable pageable);

    default List<SiemAccountBehaviorWindow> findShadowEligible(String runId,
            LocalDateTime from, LocalDateTime to, Pageable pageable) {
        return findShadowEligible(runId, from, to, 2, pageable);
    }

    List<SiemAccountBehaviorWindow> findByScoreStatusOrderByWindowStartAsc(
            BehaviorScoreStatus status, Pageable pageable);

    Page<SiemAccountBehaviorWindow> findByWindowStartGreaterThanEqualAndWindowStartLessThanAndFeatureSchemaVersionOrderByWindowStartAscIdAsc(
            LocalDateTime from, LocalDateTime to, int schemaVersion, Pageable pageable);

    @Modifying
    @Query("""
            update SiemAccountBehaviorWindow w set w.scoreStatus = :pending
            where w.scoreStatus = :ruleOnly and w.windowStart >= :since
            """)
    int markRuleOnlyPendingSince(@Param("since") LocalDateTime since,
                                 @Param("ruleOnly") BehaviorScoreStatus ruleOnly,
                                 @Param("pending") BehaviorScoreStatus pending);

    Optional<SiemAccountBehaviorWindow> findByAccountIdAndWindowStartAndFeatureSchemaVersion(
            String accountId, LocalDateTime windowStart, int featureSchemaVersion);

    List<SiemAccountBehaviorWindow> findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(
            String accountId, LocalDateTime from, LocalDateTime to);

    @Query(value = """
            select w.accountId as accountId, max(w.riskScore) as maximumRisk,
                   max(w.windowStart) as lastWindow, count(w.id) as flaggedWindows
            from SiemAccountBehaviorWindow w
            where w.windowStart >= :from and w.windowStart < :to and w.riskScore >= :minimumRisk
            group by w.accountId
            order by max(w.riskScore) desc, max(w.windowStart) desc
            """, countQuery = """
            select count(distinct w.accountId) from SiemAccountBehaviorWindow w
            where w.windowStart >= :from and w.windowStart < :to and w.riskScore >= :minimumRisk
            """)
    Page<WatchAccountProjection> findWatchAccounts(@Param("from") LocalDateTime from,
                                                    @Param("to") LocalDateTime to,
                                                    @Param("minimumRisk") int minimumRisk,
                                                    Pageable pageable);

    Page<SiemAccountBehaviorWindow> findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThanOrderByWindowStartDesc(
            String accountId, LocalDateTime from, LocalDateTime to, Pageable pageable);

    interface WatchAccountProjection {
        String getAccountId();
        Integer getMaximumRisk();
        LocalDateTime getLastWindow();
        Long getFlaggedWindows();
    }

    @Query(value = """
            select u.id as accountId,
                   max(case when w.windowStart >= :from then w.riskScore else null end) as maximumRisk,
                   max(case when w.windowStart >= :from and (:view <> 'RISK' or w.riskScore >= 45)
                       then w.windowStart else null end) as lastWindow,
                   count(distinct case when w.windowStart >= :from and w.riskScore >= 45
                       then w.windowStart else null end) as flaggedWindows,
                   count(distinct case when w.windowStart >= :historyFrom
                       then w.windowStart else null end) as historyWindows,
                   count(distinct case when w.windowStart >= :historyFrom and
            """ + AccountBaselinePolicy.TRUSTED_HQL + """
                       then w.windowStart else null end) as trustedWindows
            from User u left join SiemAccountBehaviorWindow w on w.accountId = collate(u.id as utf8mb4_unicode_ci)
                and w.windowStart >= :joinFrom and w.windowStart < :to and w.windowEnd <= :to
                and not exists (select newer.id from SiemAccountBehaviorWindow newer
                    where newer.accountId = w.accountId and newer.windowStart = w.windowStart
                      and newer.featureSchemaVersion > w.featureSchemaVersion)
            where u.deleted = false and lower(trim(u.role)) in ('customer','role_customer','khách hàng','khach hang')
            group by u.id
            having :view = 'ALL'
                or (:view = 'RISK' and count(distinct case when w.windowStart >= :from
                    and w.riskScore >= 45 then w.windowStart else null end) > 0)
                or (:view = 'BASELINE_GAPS' and count(distinct case when w.windowStart >= :historyFrom and
            """ + AccountBaselinePolicy.TRUSTED_HQL + """
                    then w.windowStart else null end) < 30)
            order by maximumRisk desc nulls last, u.id asc
            """, countQuery = """
            select count(u.id) from User u
            where u.deleted = false and lower(trim(u.role)) in ('customer','role_customer','khách hàng','khach hang')
                and (:view = 'ALL'
                    or (:view = 'RISK' and exists (select w.id from SiemAccountBehaviorWindow w
                        where w.accountId = collate(u.id as utf8mb4_unicode_ci) and w.windowStart >= :from and w.windowStart < :to
                          and w.windowEnd <= :to and w.riskScore >= 45
                          and not exists (select newer.id from SiemAccountBehaviorWindow newer
                              where newer.accountId = w.accountId and newer.windowStart = w.windowStart
                                and newer.featureSchemaVersion > w.featureSchemaVersion)))
                    or (:view = 'BASELINE_GAPS' and (select count(distinct w.windowStart)
                        from SiemAccountBehaviorWindow w where w.accountId = collate(u.id as utf8mb4_unicode_ci)
                          and w.windowStart >= :historyFrom and w.windowStart < :to and w.windowEnd <= :to and
            """ + AccountBaselinePolicy.TRUSTED_HQL + """
                          and not exists (select newer.id from SiemAccountBehaviorWindow newer
                              where newer.accountId = w.accountId and newer.windowStart = w.windowStart
                                and newer.featureSchemaVersion > w.featureSchemaVersion)) < 30))
            """)
    Page<AccountSummaryProjection> findAccountSummaries(@Param("from") LocalDateTime from,
                                                         @Param("to") LocalDateTime to,
                                                         @Param("historyFrom") LocalDateTime historyFrom,
                                                         @Param("joinFrom") LocalDateTime joinFrom,
                                                         @Param("view") String view,
                                                         Pageable pageable);

    interface AccountSummaryProjection extends WatchAccountProjection {
        Long getHistoryWindows();
        Long getTrustedWindows();
    }

    @Modifying
    @Query(value = """
            DELETE FROM siem_account_behavior_windows
            WHERE window_start < :cutoff AND score_status <> 'PENDING'
            LIMIT 1000
            """, nativeQuery = true)
    int purgeScoredBefore(@Param("cutoff") LocalDateTime cutoff);
}
