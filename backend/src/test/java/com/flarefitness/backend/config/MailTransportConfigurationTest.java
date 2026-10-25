package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

/** Loads production mail settings without connecting to SMTP or loading credentials. */
class MailTransportConfigurationTest {
    @Test void productionMailRequiresTlsAndValidatesTheServerHostname() {
        new ApplicationContextRunner().withInitializer(new ConfigDataApplicationContextInitializer())
                .withConfiguration(AutoConfigurations.of(MailSenderAutoConfiguration.class))
                .withPropertyValues("spring.mail.host=smtp.gmail.com", "spring.mail.username=mail-config-test@example.test",
                        "spring.mail.password=unused-test-value", "spring.mail.test-connection=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(JavaMailSender.class);
                    var sender=(JavaMailSenderImpl)context.getBean(JavaMailSender.class);
                    assertThat(sender.getJavaMailProperties().getProperty("mail.smtp.starttls.enable")).isEqualTo("true");
                    assertThat(sender.getJavaMailProperties().getProperty("mail.smtp.starttls.required")).isEqualTo("true");
                    assertThat(sender.getJavaMailProperties().getProperty("mail.smtp.ssl.checkserveridentity")).isEqualTo("true");
                });
    }
}
