package io.github.deshenrao.auth0lite.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt.key")
public record JwtKeyProperties(String privateKeyPem) {

    public boolean isConfigured() {
        return privateKeyPem != null && !privateKeyPem.isBlank();
    }
}
