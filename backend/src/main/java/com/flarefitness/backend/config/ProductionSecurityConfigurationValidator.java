package com.flarefitness.backend.config;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Refuses production settings that would expose authentication data or customer data in transit.
 * Local development and the private Docker MySQL service deliberately remain usable without TLS.
 */
@Component
public class ProductionSecurityConfigurationValidator implements InitializingBean {

    private static final int MINIMUM_JWT_SECRET_LENGTH = 32;

    private final Environment environment;
    private final boolean authCookieSecure;
    private final String jwtSecret;
    private final String allowedOrigins;
    private final String datasourceUrl;
    private final String datasourceUsername;
    private final String datasourcePassword;
    private final String redisPassword;
    private final String trustedProxyCidrs;

    public ProductionSecurityConfigurationValidator(
            Environment environment,
            @Value("${app.security.auth-cookie-secure}") boolean authCookieSecure,
            @Value("${app.jwt.secret}") String jwtSecret,
            @Value("${app.cors.allowed-origins}") String allowedOrigins,
            @Value("${spring.datasource.url}") String datasourceUrl,
            @Value("${spring.datasource.username}") String datasourceUsername,
            @Value("${spring.datasource.password}") String datasourcePassword,
            @Value("${spring.data.redis.password}") String redisPassword,
            @Value("${app.security.trusted-proxy-cidrs}") String trustedProxyCidrs
    ) {
        this.environment = environment;
        this.authCookieSecure = authCookieSecure;
        this.jwtSecret = jwtSecret;
        this.allowedOrigins = allowedOrigins;
        this.datasourceUrl = datasourceUrl;
        this.datasourceUsername = datasourceUsername;
        this.datasourcePassword = datasourcePassword;
        this.redisPassword = redisPassword;
        this.trustedProxyCidrs = trustedProxyCidrs;
    }

    @Override
    public void afterPropertiesSet() {
        if (!isProductionProfile()) {
            return;
        }

        validateSecureCookie();
        validateJwtSecret();
        validateCorsOrigins();
        validateExternalDatasourceTls();
        validateServiceCredentials();
        validateTrustedProxyCidrs();
    }

    private boolean isProductionProfile() {
        return Arrays.stream(environment.getActiveProfiles())
                .map(String::trim)
                .anyMatch(profile -> "prod".equalsIgnoreCase(profile) || "production".equalsIgnoreCase(profile));
    }

    private void validateSecureCookie() {
        if (!authCookieSecure) {
            throw new IllegalStateException(
                    "APP_AUTH_COOKIE_SECURE must be true when the prod/production profile is active.");
        }
    }

    private void validateJwtSecret() {
        String normalized = jwtSecret == null ? "" : jwtSecret.trim();
        if (normalized.length() < MINIMUM_JWT_SECRET_LENGTH
                || isPlaceholderSecret(normalized)
                || normalized.chars().distinct().count() < 8) {
            throw new IllegalStateException(
                    "APP_JWT_SECRET must be a non-default random value of at least 32 characters in production.");
        }
    }

    private void validateCorsOrigins() {
        if (!StringUtils.hasText(allowedOrigins)) {
            throw new IllegalStateException(
                    "APP_CORS_ALLOWED_ORIGINS must contain one or more explicit HTTPS origins in production.");
        }

        String[] origins = allowedOrigins.split(",", -1);
        for (String configuredOrigin : origins) {
            String origin = configuredOrigin.trim();
            if (!StringUtils.hasText(origin) || origin.contains("*")) {
                throw new IllegalStateException(
                        "APP_CORS_ALLOWED_ORIGINS must not contain blank or wildcard origins when credentials are enabled.");
            }
            validateHttpsOrigin(origin);
        }
    }

    private void validateExternalDatasourceTls() {
        if (isLocalOrDockerDatasource(datasourceUrl)) {
            return;
        }

        if (hasQueryParameter(datasourceUrl, "useSSL", "false")
                || !hasQueryParameter(datasourceUrl, "sslMode", "VERIFY_IDENTITY")) {
            throw new IllegalStateException(
                    "External production MySQL connections must use sslMode=VERIFY_IDENTITY and must not set useSSL=false.");
        }
    }

    private void validateServiceCredentials() {
        String normalizedDatabaseUsername = normalize(datasourceUsername);
        if (!StringUtils.hasText(normalizedDatabaseUsername)
                || "root".equalsIgnoreCase(normalizedDatabaseUsername)) {
            throw new IllegalStateException(
                    "Production must use a non-root SPRING_DATASOURCE_USERNAME with least-privilege database permissions.");
        }

        validateServiceSecret("SPRING_DATASOURCE_PASSWORD", datasourcePassword);
        validateServiceSecret("SPRING_DATA_REDIS_PASSWORD", redisPassword);
    }

    private void validateTrustedProxyCidrs() {
        String normalized = normalize(trustedProxyCidrs);
        if (!StringUtils.hasText(normalized)) {
            throw new IllegalStateException(
                    "APP_TRUSTED_PROXY_CIDRS must list the immediate Nginx/reverse-proxy CIDR in production.");
        }

        for (String configuredCidr : normalized.split(",", -1)) {
            String cidr = configuredCidr.trim();
            if (!StringUtils.hasText(cidr) || "0.0.0.0/0".equals(cidr) || "::/0".equals(cidr)) {
                throw new IllegalStateException(
                        "APP_TRUSTED_PROXY_CIDRS must not be blank or trust every address in production.");
            }
        }
    }

    private static void validateServiceSecret(String propertyName, String value) {
        String normalized = normalize(value);
        if (normalized.length() < 16 || isPlaceholderSecret(normalized) || isCommonInsecureSecret(normalized)) {
            throw new IllegalStateException(
                    propertyName + " must be a non-default random value of at least 16 characters in production.");
        }
    }

    private static boolean isPlaceholderSecret(String secret) {
        String normalized = secret.toLowerCase(Locale.ROOT);
        return normalized.startsWith("replace-")
                || normalized.startsWith("change-this")
                || normalized.startsWith("example")
                || normalized.startsWith("default")
                || normalized.startsWith("test-")
                || normalized.startsWith("flare-e2e-")
                || "replace-this-secret-with-at-least-32-characters".equals(normalized);
    }

    private static boolean isCommonInsecureSecret(String secret) {
        String normalized = secret.toLowerCase(Locale.ROOT);
        return "password".equals(normalized)
                || "password123".equals(normalized)
                || "secret".equals(normalized)
                || "redis".equals(normalized)
                || "mysql".equals(normalized);
    }

    private static void validateHttpsOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            boolean hasOnlyOriginParts = (uri.getRawPath() == null || uri.getRawPath().isEmpty())
                    && uri.getRawQuery() == null
                    && uri.getRawFragment() == null
                    && uri.getRawUserInfo() == null;
            if (!"https".equalsIgnoreCase(uri.getScheme()) || !StringUtils.hasText(uri.getHost()) || !hasOnlyOriginParts) {
                throw new IllegalStateException(
                        "APP_CORS_ALLOWED_ORIGINS must contain explicit HTTPS origins without a path, query, fragment, or credentials.");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    "APP_CORS_ALLOWED_ORIGINS contains an invalid origin: " + origin + ".", exception);
        }
    }

    private static boolean isLocalOrDockerDatasource(String jdbcUrl) {
        if (!StringUtils.hasText(jdbcUrl)) {
            return false;
        }

        try {
            String normalizedUrl = jdbcUrl.trim();
            if (!normalizedUrl.regionMatches(true, 0, "jdbc:mysql://", 0, "jdbc:mysql://".length())) {
                return false;
            }
            URI uri = URI.create(normalizedUrl.substring("jdbc:".length()));
            String host = uri.getHost();
            if (!StringUtils.hasText(host)) {
                return false;
            }
            String normalizedHost = host.toLowerCase(Locale.ROOT);
            return "db".equals(normalizedHost)
                    || "localhost".equals(normalizedHost)
                    || "::1".equals(normalizedHost)
                    || normalizedHost.startsWith("127.");
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static boolean hasQueryParameter(String jdbcUrl, String expectedName, String expectedValue) {
        if (!StringUtils.hasText(jdbcUrl)) {
            return false;
        }

        int queryStart = jdbcUrl.indexOf('?');
        if (queryStart < 0 || queryStart == jdbcUrl.length() - 1) {
            return false;
        }

        return Arrays.stream(jdbcUrl.substring(queryStart + 1).split("&"))
                .map(parameter -> parameter.split("=", 2))
                .anyMatch(parts -> parts.length == 2
                        && expectedName.equalsIgnoreCase(parts[0].trim())
                        && expectedValue.equalsIgnoreCase(parts[1].trim()));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
