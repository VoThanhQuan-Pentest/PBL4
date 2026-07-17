package com.flarefitness.backend.repository.analytics;

import com.flarefitness.backend.entity.analytics.UserBehaviorEvent;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserBehaviorEventRepository extends JpaRepository<UserBehaviorEvent, String> {

    List<UserBehaviorEvent> findTop300ByUserIdOrderByCreatedAtDesc(String userId);

    List<UserBehaviorEvent> findTop300BySessionIdOrderByCreatedAtDesc(String sessionId);

    List<UserBehaviorEvent> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    @Query("""
            select e from UserBehaviorEvent e
            where e.createdAt >= :cutoff
              and e.userId is not null and e.userId <> ''
            order by e.createdAt desc
            """)
    List<UserBehaviorEvent> findTrustedByCreatedAtAfterOrderByCreatedAtDesc(
            @Param("cutoff") LocalDateTime cutoff,
            Pageable pageable);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from UserBehaviorEvent e where e.createdAt < :cutoff")
    int deleteByCreatedAtBefore(@Param("cutoff") LocalDateTime cutoff);

    /**
     * All administration overview queries below intentionally aggregate in the database.  Loading a
     * year's worth of raw behavior events into the application process made this endpoint grow
     * linearly with traffic.
     */
    @Query("""
            select e.eventType as eventType, count(e) as eventCount
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.userId is not null and e.userId <> ''
            group by e.eventType
            """)
    List<EventTypeCount> countByEventTypeBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive
    );

    @Query("""
            select count(distinct e.userId)
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.userId is not null and e.userId <> ''
            """)
    long countDistinctAuthenticatedUsersBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive
    );

    @Query("""
            select avg(e.durationSeconds)
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PAGE_STAY
              and e.durationSeconds is not null
              and e.userId is not null and e.userId <> ''
            """)
    Double averagePageStaySecondsBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive
    );

    @Query("""
            select e.productId as metricKey,
                   sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 5
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 2
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 1
                       else 0
                   end) as score
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.productId is not null and e.productId <> ''
              and e.userId is not null and e.userId <> ''
            group by e.productId
            order by sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 5
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 2
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 1
                       else 0
                   end) desc, e.productId asc
            """)
    List<MetricValue> findTopProductMetricsBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive,
            Pageable pageable
    );

    @Query("""
            select e.categoryKey as metricKey,
                   sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) as score
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.categoryKey is not null and e.categoryKey <> ''
              and e.userId is not null and e.userId <> ''
            group by e.categoryKey
            order by sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) desc, e.categoryKey asc
            """)
    List<MetricValue> findTopCategoryMetricsBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive,
            Pageable pageable
    );

    @Query("""
            select e.priceBucket as metricKey,
                   sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) as score
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.priceBucket is not null and e.priceBucket <> ''
              and e.userId is not null and e.userId <> ''
            group by e.priceBucket
            order by sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) desc, e.priceBucket asc
            """)
    List<MetricValue> findTopPriceBucketMetricsBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive,
            Pageable pageable
    );

    @Query("""
            select e.searchKeyword as metricKey,
                   sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) as score
            from UserBehaviorEvent e
            where e.createdAt >= :fromInclusive and e.createdAt < :toExclusive
              and e.searchKeyword is not null and e.searchKeyword <> ''
              and e.userId is not null and e.userId <> ''
            group by e.searchKeyword
            order by sum(case
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_SEARCH then 4
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PURCHASE then 12
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_REVIEW then 9
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.ADD_TO_CART then 8
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.PRODUCT_VIEW then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.CATEGORY_CLICK then 3
                       when e.eventType = com.flarefitness.backend.dto.analytics.BehaviorEventType.REMOVE_FROM_CART then 2
                       else 1
                   end) desc, e.searchKeyword asc
            """)
    List<MetricValue> findTopSearchKeywordMetricsBetween(
            @Param("fromInclusive") LocalDateTime fromInclusive,
            @Param("toExclusive") LocalDateTime toExclusive,
            Pageable pageable
    );

    interface EventTypeCount {

        com.flarefitness.backend.dto.analytics.BehaviorEventType getEventType();

        long getEventCount();
    }

    interface MetricValue {

        String getMetricKey();

        Long getScore();
    }
}
