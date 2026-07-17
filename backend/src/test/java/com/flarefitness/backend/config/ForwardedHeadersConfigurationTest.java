package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

class ForwardedHeadersConfigurationTest {

    @Test
    void applicationDoesNotEnableSpringFrameworkForwardedHeaderTrust() throws IOException {
        Properties properties = new Properties();
        try (var inputStream = new ClassPathResource("application.properties").getInputStream()) {
            properties.load(inputStream);
        }

        assertThat(properties.getProperty("server.forward-headers-strategy"))
                .isEqualTo("none");
    }
}
