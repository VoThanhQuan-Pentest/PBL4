package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CorsConfigTest {

    @Test
    void permitsOnlyConfiguredCredentialedOriginsForApiRequests() {
        InspectableCorsRegistry registry = new InspectableCorsRegistry();

        new CorsConfig(" https://shop.example.com , https://admin.example.com ").addCorsMappings(registry);

        CorsConfiguration configuration = registry.configurations().get("/api/**");
        assertThat(configuration).isNotNull();
        assertThat(configuration.getAllowedOrigins())
                .containsExactly("https://shop.example.com", "https://admin.example.com");
        assertThat(configuration.getAllowCredentials()).isTrue();
        assertThat(configuration.checkOrigin("https://shop.example.com")).isEqualTo("https://shop.example.com");
        assertThat(configuration.checkOrigin("https://evil.example.com")).isNull();
        assertThat(configuration.getAllowedMethods()).contains("GET", "POST", "PATCH", "DELETE", "OPTIONS");
    }

    @Test
    void answersAllowedPreflightAndRejectsAnUnconfiguredOrigin() throws Exception {
        MockMvc mockMvc = mockMvcFor("https://shop.example.com");

        mockMvc.perform(MockMvcRequestBuilders.options("/api/ping")
                        .header(HttpHeaders.ORIGIN, "https://shop.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://shop.example.com"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));

        mockMvc.perform(MockMvcRequestBuilders.options("/api/ping")
                        .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    private static MockMvc mockMvcFor(String origins) {
        InspectableCorsRegistry registry = new InspectableCorsRegistry();
        new CorsConfig(origins).addCorsMappings(registry);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        registry.configurations().forEach(source::registerCorsConfiguration);
        return MockMvcBuilders.standaloneSetup(new PingController())
                .addFilters(new CorsFilter(source))
                .build();
    }

    private static final class InspectableCorsRegistry extends CorsRegistry {

        private Map<String, CorsConfiguration> configurations() {
            return getCorsConfigurations();
        }
    }

    @Controller
    @RequestMapping("/api")
    private static final class PingController {

        @GetMapping("/ping")
        @ResponseBody
        private String ping() {
            return "pong";
        }
    }
}
