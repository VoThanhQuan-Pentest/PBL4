package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionSecurityConfigurationValidatorTest {

    private static final String VALID_JWT_SECRET = "v8hD_0Lr7pQ1mN4xZ9cK2sT5wY6aB3dF";
    private static final String VALID_CORS_ORIGINS = "https://app.example.com,https://admin.example.com";
    private static final String DOCKER_DATASOURCE_URL =
            "jdbc:mysql://db:3306/flare_fitness?useSSL=false&allowPublicKeyRetrieval=true";
    private static final String EXTERNAL_VERIFIED_DATASOURCE_URL =
            "jdbc:mysql://database.example.com:3306/flare_fitness?sslMode=VERIFY_IDENTITY";
    private static final String VALID_DATABASE_USERNAME = "flare_app";
    private static final String VALID_DATABASE_PASSWORD = "w6Y#pL9rQ2tV5xC8";
    private static final String VALID_REDIS_PASSWORD = "r4N!kP8sW1dF7vZ3";
    private static final String VALID_TRUSTED_PROXY_CIDRS = "127.0.0.1/32,172.30.0.0/24";

    @Test
    void rejectsInsecureCookieWhenProductionProfileIsActive() {
        assertThatThrownBy(() -> productionValidator(false, VALID_JWT_SECRET, VALID_CORS_ORIGINS, DOCKER_DATASOURCE_URL)
                .afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_AUTH_COOKIE_SECURE");
    }

    @Test
    void rejectsPlaceholderJwtSecretWhenProductionProfileIsActive() {
        assertThatThrownBy(() -> productionValidator(
                true,
                "replace-with-at-least-32-random-characters",
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_JWT_SECRET");

        assertThatThrownBy(() -> productionValidator(
                true,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_JWT_SECRET");
    }

    @Test
    void rejectsWildcardAndNonHttpsCorsOriginsWhenProductionProfileIsActive() {
        assertThatThrownBy(() -> productionValidator(true, VALID_JWT_SECRET, "https://app.example.com,*", DOCKER_DATASOURCE_URL)
                .afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_CORS_ALLOWED_ORIGINS");

        assertThatThrownBy(() -> productionValidator(true, VALID_JWT_SECRET, "http://app.example.com", DOCKER_DATASOURCE_URL)
                .afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_CORS_ALLOWED_ORIGINS");
    }

    @Test
    void rejectsUnverifiedExternalDatasourceWhenProductionProfileIsActive() {
        String unverifiedUrl = "jdbc:mysql://database.example.com:3306/flare_fitness?useSSL=false";

        assertThatThrownBy(() -> productionValidator(true, VALID_JWT_SECRET, VALID_CORS_ORIGINS, unverifiedUrl)
                .afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sslMode=VERIFY_IDENTITY");
    }

    @Test
    void rejectsDefaultServiceCredentialsAndUnsafeTrustedProxyRangesInProduction() {
        assertThatThrownBy(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL,
                "root",
                VALID_DATABASE_PASSWORD,
                VALID_REDIS_PASSWORD,
                VALID_TRUSTED_PROXY_CIDRS
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SPRING_DATASOURCE_USERNAME");

        assertThatThrownBy(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL,
                VALID_DATABASE_USERNAME,
                "change-this-database-password",
                VALID_REDIS_PASSWORD,
                VALID_TRUSTED_PROXY_CIDRS
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SPRING_DATASOURCE_PASSWORD");

        assertThatThrownBy(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL,
                VALID_DATABASE_USERNAME,
                VALID_DATABASE_PASSWORD,
                VALID_REDIS_PASSWORD,
                "0.0.0.0/0"
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_TRUSTED_PROXY_CIDRS");
    }

    @Test
    void rejectsTrailingPathInProductionCorsOrigin() {
        assertThatThrownBy(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                "https://app.example.com/",
                DOCKER_DATASOURCE_URL
        ).afterPropertiesSet())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_CORS_ALLOWED_ORIGINS");
    }

    @Test
    void permitsVerifiedExternalDatasourceAndPrivateDockerDatasourceInProduction() {
        assertThatCode(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                VALID_CORS_ORIGINS,
                EXTERNAL_VERIFIED_DATASOURCE_URL
        ).afterPropertiesSet()).doesNotThrowAnyException();

        assertThatCode(() -> productionValidator(
                true,
                VALID_JWT_SECRET,
                VALID_CORS_ORIGINS,
                DOCKER_DATASOURCE_URL
        ).afterPropertiesSet()).doesNotThrowAnyException();
    }

    @Test
    void permitsLocalDevelopmentConfiguration() {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles("dev");

        assertThatCode(() -> new ProductionSecurityConfigurationValidator(
                environment,
                false,
                "short",
                "*",
                "jdbc:mysql://database.example.com:3306/flare_fitness?useSSL=false",
                "root",
                "short",
                "short",
                ""
        ).afterPropertiesSet())
                .doesNotThrowAnyException();
    }

    private static ProductionSecurityConfigurationValidator productionValidator(
            boolean authCookieSecure,
            String jwtSecret,
            String allowedOrigins,
            String datasourceUrl
    ) {
        return productionValidator(
                authCookieSecure,
                jwtSecret,
                allowedOrigins,
                datasourceUrl,
                VALID_DATABASE_USERNAME,
                VALID_DATABASE_PASSWORD,
                VALID_REDIS_PASSWORD,
                VALID_TRUSTED_PROXY_CIDRS
        );
    }

    private static ProductionSecurityConfigurationValidator productionValidator(
            boolean authCookieSecure,
            String jwtSecret,
            String allowedOrigins,
            String datasourceUrl,
            String datasourceUsername,
            String datasourcePassword,
            String redisPassword,
            String trustedProxyCidrs
    ) {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles("prod");
        return new ProductionSecurityConfigurationValidator(
                environment,
                authCookieSecure,
                jwtSecret,
                allowedOrigins,
                datasourceUrl,
                datasourceUsername,
                datasourcePassword,
                redisPassword,
                trustedProxyCidrs
        );
    }
}
