package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class UserLoginIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void loginSucceedsWithCorrectCredentials() {
        String email = "login.success@example.com";
        register(email, PASSWORD);

        ResponseEntity<LoginResponse> response = attemptLogin(email, PASSWORD, LoginResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        LoginResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.tokens().tokenType()).isEqualTo("Bearer");
        assertThat(body.tokens().accessToken()).isNotBlank();
        assertThat(body.tokens().refreshToken()).isNotBlank();
        assertThat(body.tokens().expiresInSeconds()).isPositive();
        assertThat(body.user().email()).isEqualTo(email);
        assertThat(body.user().roles()).containsExactly("USER");
    }

    @Test
    void loginReturnsIdenticalGenericMessageForUnknownEmailAndWrongPassword() {
        String email = "wrong.password@example.com";
        register(email, PASSWORD);

        ResponseEntity<String> wrongPassword = attemptLogin(email, "TotallyWrongPassword1!", String.class);
        ResponseEntity<String> unknownEmail = attemptLogin("no.such.user@example.com", PASSWORD, String.class);

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownEmail.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(wrongPassword.getBody()).isEqualTo(unknownEmail.getBody());
    }

    @Test
    void loginLocksAccountAfterFiveFailedAttemptsAndRejectsEvenCorrectPassword() {
        String email = "lockout.target@example.com";
        register(email, PASSWORD);

        for (int attempt = 0; attempt < 5; attempt++) {
            ResponseEntity<String> response = attemptLogin(email, "WrongPassword123!", String.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        ResponseEntity<String> lockedWithCorrectPassword = attemptLogin(email, PASSWORD, String.class);

        assertThat(lockedWithCorrectPassword.getStatusCode()).isEqualTo(HttpStatus.LOCKED);
        assertThat(lockedWithCorrectPassword.getHeaders().get(HttpHeaders.RETRY_AFTER)).isNotNull();
    }

    private void register(String email, String password) {
        RegisterUserRequest request = new RegisterUserRequest(email, password);
        restTemplate.postForEntity("/api/v1/auth/register", request, UserResponse.class);
    }

    private <T> ResponseEntity<T> attemptLogin(String email, String password, Class<T> responseType) {
        LoginRequest request = new LoginRequest(email, password);
        return restTemplate.postForEntity("/api/v1/auth/login", request, responseType);
    }
}
