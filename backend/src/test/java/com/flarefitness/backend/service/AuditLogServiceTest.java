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
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class AuditLogServiceTest {

    private Logger auditLogger;
    private ListAppender<ILoggingEvent> appender;
    private ch.qos.logback.classic.Level previousLevel;

    @BeforeEach
    void setUp() {
        auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        previousLevel = auditLogger.getLevel();
        auditLogger.setLevel(ch.qos.logback.classic.Level.INFO);
        appender = new ListAppender<>();
        appender.start();
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
        MDC.clear();
        auditLogger.detachAppender(appender);
        appender.stop();
        auditLogger.setLevel(previousLevel);
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

    @Test
    void successfulFactorRecordWaitsForCommitAndKeepsItsOriginalTrace() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        MDC.put("traceId", "owned-original-trace");
        new AuditLogService().success("AUTH_LOGIN_EMAIL_OTP_VERIFIED", "user-1", "user-1", "AUTH_FACTOR", "EMAIL_OTP");
        assertThat(appender.list).isEmpty();
        MDC.put("traceId", "owned-later-trace");
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);
        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getFormattedMessage()).contains("traceId=owned-original-trace");
            assertThat(event.getFormattedMessage()).doesNotContain("owned-later-trace");
        });
    }

    @Test
    void rollbackDiscardsFactorSuccessButRetainsImmediateRejection() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        var audit = new AuditLogService();
        audit.success("AUTH_LOGIN_EMAIL_OTP_ISSUED", null, "user-1", "AUTH_FACTOR", "EMAIL_OTP");
        audit.failure("AUTH_LOGIN_EMAIL_OTP_REJECTED", null, null, "AUTH_FACTOR", "EMAIL_OTP");
        TransactionSynchronizationManager.getSynchronizations()
                .forEach(callback -> callback.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        assertThat(appender.list).singleElement().satisfies(event ->
                assertThat(event.getFormattedMessage()).startsWith("action=AUTH_LOGIN_EMAIL_OTP_REJECTED outcome=FAILURE "));
    }
}
