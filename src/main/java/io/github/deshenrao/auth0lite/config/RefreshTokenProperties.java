package io.github.deshenrao.auth0lite.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.refresh-token")
public record RefreshTokenProperties(Duration ttl) {
}
