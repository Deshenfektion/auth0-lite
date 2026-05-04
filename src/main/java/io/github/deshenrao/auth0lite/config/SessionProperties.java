package io.github.deshenrao.auth0lite.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.session")
public record SessionProperties(Duration absoluteTtl) {
}
