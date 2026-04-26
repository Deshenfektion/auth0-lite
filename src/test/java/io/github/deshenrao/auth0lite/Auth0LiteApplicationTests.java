package io.github.deshenrao.auth0lite;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
class Auth0LiteApplicationTests {

    @Test
    void contextLoads() {
    }
}
