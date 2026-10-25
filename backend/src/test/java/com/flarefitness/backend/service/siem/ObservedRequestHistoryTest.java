package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class ObservedRequestHistoryTest {
    private static final LocalDateTime AS_OF = LocalDateTime.of(2026, 10, 1, 0, 0);

    @Test void shortHistoryIncludesObservedRiskyAndLabeledHttpWithoutChangingTrustedBaselineReadiness() {
        var risky = window(AS_OF.minusMinutes(30), 9, "ABNORMAL");
        risky.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment("test-model", 99.0, 90, "test fixture", 1), AS_OF);
        var mixed = window(AS_OF.minusMinutes(15), 99, "MIXED");
        var history = List.of(risky, mixed);
        var observed = AccountBaselinePolicy.observedRequests(history, AS_OF);
        assertThat(observed.windowCount()).isEqualTo(2);
        assertThat(observed.medianLogRequestCount()).isCloseTo((Math.log(10) + Math.log(100)) / 2, within(1e-12));
        var trusted = AccountBaselinePolicy.summarize(history, AS_OF, ZoneId.of("Asia/Ho_Chi_Minh"));
        assertThat(trusted.trustedWindows()).isZero();
        assertThat(trusted.status()).isEqualTo("INSUFFICIENT_HISTORY");
        assertThat(trusted.features().established()).isFalse();
    }

    @Test void pastOnlyFourteenDayWindowExcludesFutureStaleAndZeroHttpButIncludesEndEqualToAsOf() {
        var oldest = window(AS_OF.minusDays(14), 9, "REAL");
        var latest = window(AS_OF.minusMinutes(15), 99, "REAL");
        var stale = window(AS_OF.minusDays(14).minusSeconds(1), 999, "REAL");
        var overlapping = window(AS_OF.minusMinutes(14), 999, "REAL");
        var future = window(AS_OF, 999, "REAL");
        var empty = window(AS_OF.minusMinutes(45), 0, "REAL");
        var observed = AccountBaselinePolicy.observedRequests(List.of(oldest, latest, stale, overlapping, future, empty), AS_OF);
        assertThat(observed.windowCount()).isEqualTo(2);
        assertThat(observed.medianLogRequestCount()).isCloseTo((Math.log(10) + Math.log(100)) / 2, within(1e-12));
        assertThat(AccountBaselinePolicy.observedRequests(List.of(stale, overlapping, future, empty), AS_OF))
                .isEqualTo(new AccountBaselinePolicy.ObservedRequestHistory(0, 0));
    }

    @Test void historyDeduplicatesWindowStartsAndBoundsTheMostRecentObservedWindows() {
        var duplicate = window(AS_OF.minusMinutes(15), 9, "REAL");
        assertThat(AccountBaselinePolicy.observedRequests(List.of(duplicate, duplicate), AS_OF).windowCount()).isEqualTo(1);
        var many = IntStream.range(0, 1500).mapToObj(index -> window(AS_OF.minusDays(3).plusMinutes(index),
                index < 156 ? 999 : 9, "REAL")).toList();
        var observed = AccountBaselinePolicy.observedRequests(many, AS_OF);
        assertThat(observed.windowCount()).isEqualTo(1344);
        assertThat(observed.medianLogRequestCount()).isCloseTo(Math.log(10), within(1e-12));
    }

    @Test void malformedHistorySummariesAndWindowsAreRejected() {
        for (var pair : List.of(new double[] {-1, 0}, new double[] {1345, 0}, new double[] {0, 1}, new double[] {1, -1})) {
            assertThatThrownBy(() -> new AccountBaselinePolicy.ObservedRequestHistory((int) pair[0], pair[1]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        var invalid = window(AS_OF.minusMinutes(15), 9, "REAL"); invalid.setWindowEnd(invalid.getWindowStart());
        assertThatThrownBy(() -> AccountBaselinePolicy.observedRequests(List.of(invalid), AS_OF))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static SiemAccountBehaviorWindow window(LocalDateTime start, int requests, String label) {
        var row = new SiemAccountBehaviorWindow(); row.setWindowStart(start); row.setWindowEnd(start.plusMinutes(15));
        row.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                List.of((double) requests, 0.0, 0.0, 0.0, 0.0, 0.0, requests == 0 ? 0.0 : 1.0, 1.0, 0.0, 0.0, 0.0)),
                requests, false, "203.0.113.1", "OTHER", label, AS_OF);
        return row;
    }
}
