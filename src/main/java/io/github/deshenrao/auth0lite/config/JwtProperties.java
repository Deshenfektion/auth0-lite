package io.github.deshenrao.auth0lite.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String issuer, String audience, Duration accessTokenTtl) {
}
