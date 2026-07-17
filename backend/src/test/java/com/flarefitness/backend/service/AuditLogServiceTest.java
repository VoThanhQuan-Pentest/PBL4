package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

class AuditLogServiceTest {

    private Logger auditLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setUp() {
        auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        appender = new ListAppender<>();
        appender.start();
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        MDC.clear();
        auditLogger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void writesSanitizedStructuredEventWithCorrelationTraceId() {
        MDC.put("traceId", "trace-123");

        new AuditLogService().success(
                "ORDER CREATE",
                "user-1\nforged-field",
                "user-2",
                "ORDER",
                "order-1");

        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getFormattedMessage()).contains("action=ORDER_CREATE");
            assertThat(event.getFormattedMessage()).contains("actorId=user-1_forged-field");
            assertThat(event.getFormattedMessage()).contains("traceId=trace-123");
            assertThat(event.getFormattedMessage()).doesNotContain("\n");
        });
    }
}
