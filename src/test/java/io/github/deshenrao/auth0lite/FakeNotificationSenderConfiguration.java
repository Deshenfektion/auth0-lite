package io.github.deshenrao.auth0lite;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration
public class FakeNotificationSenderConfiguration {

    @Bean
    @Primary
    public CapturingNotificationSender notificationSender() {
        return new CapturingNotificationSender();
    }
}
