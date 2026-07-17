package com.flarefitness.backend.service.analytics;

import static org.mockito.Mockito.verify;

import com.flarefitness.backend.repository.analytics.UserBehaviorEventRepository;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BehaviorAnalyticsRetentionServiceTest {

    @Mock
    private UserBehaviorEventRepository eventRepository;

    @Test
    void deletesOnlyEventsOutsideConfiguredRetentionWindow() {
        BehaviorAnalyticsRetentionService service = new BehaviorAnalyticsRetentionService(eventRepository, 400);
        LocalDateTime now = LocalDateTime.of(2026, 7, 14, 3, 20);

        service.purgeExpiredEvents(now);

        verify(eventRepository).deleteByCreatedAtBefore(now.minusDays(400));
    }

    @Test
    void neverPurgesDataNeededByThe366DayDashboard() {
        BehaviorAnalyticsRetentionService service = new BehaviorAnalyticsRetentionService(eventRepository, 30);
        LocalDateTime now = LocalDateTime.of(2026, 7, 14, 3, 20);

        service.purgeExpiredEvents(now);

        verify(eventRepository).deleteByCreatedAtBefore(now.minusDays(366));
    }
}
