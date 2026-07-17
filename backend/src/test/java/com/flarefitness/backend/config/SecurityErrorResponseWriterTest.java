package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.flarefitness.backend.exception.ApiErrorResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;

class SecurityErrorResponseWriterTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void writesTheSameStableErrorContractWithTheRequestTraceId() throws Exception {
        MDC.put("traceId", "trace-12345678");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityErrorResponseWriter writer = new SecurityErrorResponseWriter(new ObjectMapper().findAndRegisterModules());

        writer.write(response, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Can dang nhap.");

        ApiErrorResponse body = new ObjectMapper().findAndRegisterModules().readValue(
                response.getContentAsString(StandardCharsets.UTF_8), ApiErrorResponse.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(body.code()).isEqualTo("UNAUTHORIZED");
        assertThat(body.message()).isEqualTo("Can dang nhap.");
        assertThat(body.traceId()).isEqualTo("trace-12345678");
    }

    @Test
    void preservesCamelCaseTraceIdWithTheApplicationSnakeCaseNamingStrategy() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

        String serialized = objectMapper.writeValueAsString(new ApiErrorResponse(
                java.time.OffsetDateTime.parse("2026-07-15T00:00:00Z"),
                400,
                "Bad Request",
                "Du lieu khong hop le.",
                "BAD_REQUEST",
                "trace-12345678"));

        assertThat(serialized).contains("\"traceId\":\"trace-12345678\"");
        assertThat(serialized).doesNotContain("\"trace_id\"");
    }
}
