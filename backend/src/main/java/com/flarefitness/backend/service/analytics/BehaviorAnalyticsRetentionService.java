package com.flarefitness.backend.service.analytics;

import com.flarefitness.backend.repository.analytics.UserBehaviorEventRepository;
import java.time.LocalDateTime;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The admin dashboard reports at most 366 days of behavior data. Retain a small
 * operational buffer above that period, then delete old raw events in the
 * database instead of letting the table grow forever.
 */
@Service
public class BehaviorAnalyticsRetentionService {

    private static final int MIN_RETENTION_DAYS = 366;

    private final UserBehaviorEventRepository eventRepository;
    private final int retentionDays;

    public BehaviorAnalyticsRetentionService(
            UserBehaviorEventRepository eventRepository,
            @Value("${app.analytics.retention-days}") int retentionDays) {
        this.eventRepository = eventRepository;
        this.retentionDays = Math.max(MIN_RETENTION_DAYS, retentionDays);
    }

    @Scheduled(cron = "${app.analytics.retention-cron}")
    @Transactional
    public void purgeExpiredEvents() {
        purgeExpiredEvents(LocalDateTime.now());
    }

    @Transactional
    void purgeExpiredEvents(LocalDateTime now) {
        eventRepository.deleteByCreatedAtBefore(now.minusDays(retentionDays));
    }
}
