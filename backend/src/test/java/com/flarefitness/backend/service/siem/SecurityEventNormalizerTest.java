package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SecurityEventNormalizerTest {
    static Stream<Arguments> pathsAndAgents() {
        return Stream.of("admin/users", "profile", "orders", "support", "reviews", "promo-hunt", "sync", "products", "owned-missing")
                .flatMap(path -> Stream.of("Mozilla Chrome/126", "Mozilla Firefox/120", "Mozilla Safari/17", "Mozilla Edg/126", "owned-scanner")
                        .map(agent -> Arguments.of("/api/" + path, agent)));
    }

    @ParameterizedTest @MethodSource("pathsAndAgents")
    void onlyServerVocabularyCanBeExported(String path, String agent) {
        assertThat(SecurityEventNormalizer.REQUEST_GROUPS).contains(SecurityEventNormalizer.routeGroup(path));
        assertThat(SecurityEventNormalizer.AGENT_FAMILIES).contains(SecurityEventNormalizer.userAgentFamily(agent));
        assertThat(SecurityEventNormalizer.userAgentFamily("owned-scanner")).isEqualTo("OTHER");
    }

    @Test void excludedTelemetryAndQueriesAreNotAccidentallyAddedToAccountFeatures() {
        for (String path : List.of("/", "/api/health", "/api/auth/login", "/api/analytics/events", "/api/siem/status"))
            assertThat(SecurityEventNormalizer.routeGroup(path)).isNull();
        assertThatThrownBy(() -> SecurityEventNormalizer.routeGroup("/api/products?secret=not-kept"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
