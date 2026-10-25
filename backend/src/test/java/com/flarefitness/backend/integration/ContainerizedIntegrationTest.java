package com.flarefitness.backend.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.junit.jupiter.api.TestInstance;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class ContainerizedIntegrationTest {

    @Autowired(required = false) private Environment testEnvironment;
    @Autowired(required = false) private StringRedisTemplate testRedis;

    private static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName
            .parse("mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
            .asCompatibleSubstituteFor("mysql"))
            .withDatabaseName("flare_fitness")
            .withUsername("flare")
            .withPassword("flare-test-password")
            .withCreateContainerCmdModifier(command -> bindLiveLab(command, 3306, 768));

    private static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99")
            .withExposedPorts(6379)
            .withCommand("redis-server", "--save", "", "--appendonly", "no", "--requirepass", "flare-test-redis")
            .withCreateContainerCmdModifier(command -> bindLiveLab(command, 6379, 128));

    static void bindLiveLab(com.github.dockerjava.api.command.CreateContainerCmd command, int port, int memoryMb) {
        boolean controlled = "true".equals(System.getenv("FLARE_CONTROLLED_ACTION_TRIAL"));
        if (!controlled && !"true".equals(System.getenv("FLARE_LIVE_PROFILE_SMOKE"))) return;
        boolean projectObserve = "true".equals(System.getenv("FLARE_POSTLOGIN_OBSERVE"));
        int memory = projectObserve ? (port == 3306 ? 1024 : 64) : controlled && port == 3306 ? 512 : memoryMb;
        if (projectObserve) command.withLabels(new java.util.HashMap<>(java.util.Map.of(
                "flare.postlogin.implementation","legacy-20261022","flare.postlogin.unit","project-observe")));
        command.getHostConfig().withMemory(memory * 1024L * 1024L).withNanoCPUs(1_000_000_000L)
                .withPortBindings(new com.github.dockerjava.api.model.PortBinding(
                        com.github.dockerjava.api.model.Ports.Binding.bindIp("127.0.0.1"), new com.github.dockerjava.api.model.ExposedPort(port)));
        String cpuset = System.getenv("FLARE_LAB_CPUSET");
        if (cpuset != null) command.getHostConfig().withCpusetCpus(cpuset);
    }

    static String mailSetting(String key, String fallback) {
        if (!"true".equals(System.getenv("FLARE_LIVE_PROFILE_SMOKE"))) return fallback;
        String value = System.getenv(key);
        if (value == null || value.isBlank()) throw new IllegalStateException("Live mail configuration missing");
        return value;
    }

    static {
        MYSQL.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // Suppliers must return the same value throughout one context's life.
        String namespace = "ci:" + java.util.UUID.randomUUID() + ":";
        registry.add("flare.test.redis-namespace", () -> namespace);
        for (String property : java.util.List.of("app.security.token-prefix", "app.security.user-token-prefix",
                "app.security.login-attempt-prefix", "app.security.password-reset-token-prefix",
                "app.otp.redis-prefix", "app.cache.product-prefix", "app.cache.recommendation-prefix")) {
            registry.add(property, () -> namespace + property + ":");
        }
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.password", () -> "flare-test-redis");
        registry.add("app.jwt.secret", () -> "test-only-jwt-secret-at-least-thirty-two-characters");
        registry.add("app.mail.from", () -> mailSetting("APP_MAIL_FROM", "test@flarefitness.local"));
        registry.add("spring.mail.username", () -> mailSetting("APP_MAIL_USERNAME", "test@flarefitness.local"));
        registry.add("spring.mail.password", () -> mailSetting("APP_MAIL_PASSWORD", "not-used-in-tests"));
        registry.add("app.security.auth-cookie-secure", () -> "false");
    }

    @BeforeEach
    void clearOnlyOwnedRedisFixtures() {
        if (testRedis == null || testEnvironment == null) return;
        String namespace = testEnvironment.getRequiredProperty("flare.test.redis-namespace");
        if (!namespace.matches("ci:[0-9a-f-]{36}:")) throw new IllegalStateException("Unsafe test namespace");
        try (var cursor = testRedis.scan(ScanOptions.scanOptions().match(namespace + "*").count(100).build())) {
            var batch = new java.util.ArrayList<String>(100);
            while (cursor.hasNext()) {
                batch.add(cursor.next());
                if (batch.size() == 100) { testRedis.delete(batch); batch.clear(); }
            }
            if (!batch.isEmpty()) testRedis.delete(batch);
        }
    }

    @BeforeAll
    static void assertContainersAreReady() {
        if (!MYSQL.isRunning() || !REDIS.isRunning()) {
            throw new IllegalStateException("Integration containers are not running.");
        }
    }

}
