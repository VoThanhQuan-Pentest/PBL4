package com.flarefitness.backend.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class ContainerizedIntegrationTest {

    private static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName
            .parse("mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
            .asCompatibleSubstituteFor("mysql"))
            .withDatabaseName("flare_fitness")
            .withUsername("flare")
            .withPassword("flare-test-password");

    private static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99")
            .withExposedPorts(6379)
            .withCommand("redis-server", "--save", "", "--appendonly", "no", "--requirepass", "flare-test-redis");

    static {
        MYSQL.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.password", () -> "flare-test-redis");
        registry.add("app.jwt.secret", () -> "test-only-jwt-secret-at-least-thirty-two-characters");
        registry.add("app.mail.from", () -> "test@flarefitness.local");
        registry.add("spring.mail.username", () -> "test@flarefitness.local");
        registry.add("spring.mail.password", () -> "not-used-in-tests");
        registry.add("app.security.auth-cookie-secure", () -> "false");
    }

    @BeforeAll
    static void assertContainersAreReady() {
        if (!MYSQL.isRunning() || !REDIS.isRunning()) {
            throw new IllegalStateException("Integration containers are not running.");
        }
    }

}
