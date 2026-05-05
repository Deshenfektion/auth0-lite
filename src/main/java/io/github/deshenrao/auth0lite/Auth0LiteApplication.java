package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.config.JwtProperties;
import io.github.deshenrao.auth0lite.config.RefreshTokenProperties;
import io.github.deshenrao.auth0lite.config.SessionProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({JwtProperties.class, RefreshTokenProperties.class, SessionProperties.class})
public class Auth0LiteApplication {

    public static void main(String[] args) {
        SpringApplication.run(Auth0LiteApplication.class, args);
    }
}
