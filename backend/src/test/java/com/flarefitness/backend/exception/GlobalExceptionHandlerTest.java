package com.flarefitness.backend.exception;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.sql.SQLIntegrityConstraintViolationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

class GlobalExceptionHandlerTest {

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        MDC.clear();
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void dataIntegrityLogContainsOnlySanitizedCauseTypeAndTraceId() {
        MDC.put("traceId", "trace-123");
        String sensitiveValue = "private@example.com";
        var databaseCause = new SQLIntegrityConstraintViolationException(
                "Duplicate entry '" + sensitiveValue + "' for key users.email");
        var exception = new DataIntegrityViolationException(
                "Could not save customer " + sensitiveValue, databaseCause);

        ResponseEntity<ApiErrorResponse> response = new GlobalExceptionHandler().handleDataIntegrity(exception);

        assertThat(response.getBody()).isNotNull().satisfies(body -> {
            assertThat(body.status()).isEqualTo(400);
            assertThat(body.code()).isEqualTo("DATA_CONSTRAINT_VIOLATION");
            assertThat(body.traceId()).isEqualTo("trace-123");
        });
        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getFormattedMessage())
                    .contains("causeType=SQLIntegrityConstraintViolationException")
                    .contains("traceId=trace-123")
                    .doesNotContain(sensitiveValue)
                    .doesNotContain("Duplicate entry")
                    .doesNotContain("Could not save customer");
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @Test
    void resourceGoneUsesStableHttpAndErrorCode() {
        ResponseEntity<ApiErrorResponse> response = new GlobalExceptionHandler()
                .handleGone(new ResourceGoneException("Tai nguyen dong bo da ngung ho tro."));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.GONE);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().code()).isEqualTo("RESOURCE_GONE");
    }

    @Test
    void unmatchedRoutesUseSanitized404WithoutInternalErrorLogging() {
        MDC.put("traceId", "missing-route-123");
        String rawPath = "/api/private/attacker-path-canary";
        var handler = new GlobalExceptionHandler();
        for (Exception exception : java.util.List.of(
                new NoResourceFoundException(HttpMethod.GET, rawPath),
                new NoHandlerFoundException("GET", rawPath, HttpHeaders.EMPTY))) {
            var response = handler.handleMissingRoute(exception);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody()).isNotNull().satisfies(body -> {
                assertThat(body.status()).isEqualTo(404);
                assertThat(body.code()).isEqualTo("RESOURCE_NOT_FOUND");
                assertThat(body.traceId()).isEqualTo("missing-route-123");
                assertThat(body.message()).doesNotContain(rawPath, "static resource");
            });
        }
        assertThat(appender.list).isEmpty();
    }
}
