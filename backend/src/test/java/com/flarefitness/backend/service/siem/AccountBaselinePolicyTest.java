package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class AccountBaselinePolicyTest {
    private static final LocalDateTime AS_OF = LocalDateTime.of(2026, 9, 30, 12, 0);
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    static Stream<Arguments> maturityCases() {
        return IntStream.of(0, 1, 14, 29, 30, 31, 60, 96).boxed().flatMap(count ->
                IntStream.range(0, 5).boxed().flatMap(boundary ->
                        IntStream.range(0, 10).mapToObj(trust -> Arguments.of(count, boundary, trust))));
    }

    @ParameterizedTest(name = "count={0},boundary={1},trust={2}")
    @MethodSource("maturityCases")
    void countsDistinctCompletedTrustedHistoryWithoutFutureLeakage(int count, int boundary, int trust) {
        List<SiemAccountBehaviorWindow> history = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            LocalDateTime start = index == 0 ? switch (boundary) {
                case 0 -> AS_OF.minusHours(1);
                case 1 -> AS_OF.minusDays(14);
                case 2 -> AS_OF.minusDays(14).minusMinutes(15);
                case 3 -> AS_OF;
                default -> AS_OF.minusMinutes(5);
            } : AS_OF.minusDays(2).plusMinutes(15L * index);
            history.add(window(index, start, index == 0 ? trust : 0));
        }
        int included = count == 0 ? 0 : count - (boundary >= 2 ? 1 : 0);
        int trusted = included - (count > 0 && boundary < 2 && trust != 0 ? 1 : 0);
        String expected = included == 0 ? "NO_DATA" : trusted < 30 ? "INSUFFICIENT_HISTORY" : "READY";
        var snapshot = AccountBaselinePolicy.summarize(history, AS_OF, ZONE);
        assertThat(snapshot.status()).isEqualTo(expected);
        assertThat(snapshot.trustedWindows()).isEqualTo(trusted);
        assertThat(snapshot.features().established()).isEqualTo(trusted >= 30);
        assertThat(snapshot.asOf()).isEqualTo(AS_OF);
        if (trusted < 30) {
            assertThat(snapshot.features().seenIps()).isEmpty();
            assertThat(snapshot.features().usualHours()).isEmpty();
        }
    }

    @Test
    void duplicateSnapshotsDoNotManufactureMaturity() {
        var one = window(1, AS_OF.minusHours(1), 0);
        var snapshot = AccountBaselinePolicy.summarize(java.util.Collections.nCopies(40, one), AS_OF, ZONE);
        assertThat(snapshot.trustedWindows()).isEqualTo(1);
        assertThat(snapshot.status()).isEqualTo("INSUFFICIENT_HISTORY");
    }

    @Test
    void malformedHistoryIsRejectedRatherThanCountedAsReady() {
        assertThatThrownBy(() -> AccountBaselinePolicy.summarize(List.of(new SiemAccountBehaviorWindow()), AS_OF, ZONE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static SiemAccountBehaviorWindow window(int index, LocalDateTime start, int trust) {
        List<Double> vector = new ArrayList<>(List.of(4.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0));
        if (trust == 1) vector.set(1, 1.0);
        if (trust == 2) vector.set(2, 1.0);
        if (trust == 3) vector.set(3, 1.0);
        if (trust == 4) vector.set(5, 1.0);
        if (trust == 5) vector.set(8, 1.0);
        if (trust == 6) vector.set(9, 1.0);
        String label = trust == 7 ? "ABNORMAL" : trust == 8 ? "MIXED" : "NORMAL";
        var result = new SiemAccountBehaviorWindow();
        result.setId("baseline-case-" + index);
        result.setAccountId("baseline-owned-account");
        result.setWindowStart(start);
        result.setWindowEnd(start.plusMinutes(15));
        result.replaceFeatures(new AccountBehaviorFeatures.Vector(1, vector), 6, false,
                "198.51.100.1", "CHROMIUM", label, AS_OF);
        if (trust == 9) result.recordAssessment(
                new SiemAccountBehaviorWindow.AccountRiskAssessment(null, null, 30, "case risk boundary"), AS_OF);
        return result;
    }
}
