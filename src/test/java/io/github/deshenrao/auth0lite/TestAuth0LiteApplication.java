package io.github.deshenrao.auth0lite;

import org.springframework.boot.SpringApplication;

public class TestAuth0LiteApplication {

    public static void main(String[] args) {
        SpringApplication.from(Auth0LiteApplication::main)
                .with(TestcontainersConfiguration.class)
                .run(args);
    }
}
