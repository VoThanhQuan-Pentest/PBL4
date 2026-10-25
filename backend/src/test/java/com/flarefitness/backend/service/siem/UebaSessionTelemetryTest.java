package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class UebaSessionTelemetryTest {
    private static final String JTI = "4e86ad52-994e-4e6e-a39d-6bc9df3f8537";
    private static final Instant ISSUED = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void pseudonymIsStableDomainSeparatedAndScopedToBothActorAndRandomSession() {
        var first = UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI, ISSUED).orElseThrow();
        assertThat(first).isEqualTo(UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI, ISSUED).orElseThrow());
        assertThat(first.sessionPseudonym()).matches("[0-9a-f]{64}").doesNotContain(JTI, "customer-1");
        assertThat(first.sessionIssuedAt()).isEqualTo(LocalDateTime.ofInstant(ISSUED, ZoneOffset.UTC));
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-2", JTI, ISSUED).orElseThrow().sessionPseudonym())
                .isNotEqualTo(first.sessionPseudonym());
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1",
                "4e86ad52-994e-4e6e-a39d-6bc9df3f8538", ISSUED).orElseThrow().sessionPseudonym())
                .isNotEqualTo(first.sessionPseudonym());
    }

    @Test
    void missingMalformedNonRandomOrFutureMetadataIsAbsent() {
        assertThat(UebaSessionTelemetry.fromVerifiedClaims(null, JTI, ISSUED)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("", JTI, ISSUED)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", null, ISSUED)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI.toUpperCase(), ISSUED)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", "00000000-0000-0000-0000-000000000000", ISSUED)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI, null)).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI, Instant.now().plusSeconds(60))).isEmpty();
        assertThat(UebaSessionTelemetry.fromVerifiedClaims("customer-1", JTI, Instant.EPOCH)).isEmpty();
        assertThatThrownBy(() -> new UebaSessionTelemetry(JTI, LocalDateTime.now())).isInstanceOf(IllegalArgumentException.class);
    }
}
