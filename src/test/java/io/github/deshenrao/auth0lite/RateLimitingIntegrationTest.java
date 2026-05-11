package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.ForgotPasswordRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@TestPropertySource(properties = {
        "app.rate-limit.capacity=3",
        "app.rate-limit.refill-period=PT10M"
})
class RateLimitingIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void exceedingTheRateLimitReturns429WithARetryAfterHeader() {
        for (int attempt = 0; attempt < 3; attempt++) {
            ResponseEntity<String> response = attemptForgotPassword();
            assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        ResponseEntity<String> limited = attemptForgotPassword();

        assertThat(limited.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(limited.getHeaders().get(HttpHeaders.RETRY_AFTER)).isNotNull();
    }

    @Test
    void endpointsOutsideTheRateLimitedSetAreUnaffected() {
        for (int attempt = 0; attempt < 5; attempt++) {
            ResponseEntity<String> response = restTemplate.getForEntity("/actuator/health", String.class);
            assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    private ResponseEntity<String> attemptForgotPassword() {
        return restTemplate.postForEntity(
                "/api/v1/account/forgot-password",
                new ForgotPasswordRequest("rate.limit.test@example.com"),
                String.class);
    }
}
