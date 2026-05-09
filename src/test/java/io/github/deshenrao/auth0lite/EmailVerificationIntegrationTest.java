package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.ResendVerificationRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.dto.VerifyEmailRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({TestcontainersConfiguration.class, FakeNotificationSenderConfiguration.class})
class EmailVerificationIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private CapturingNotificationSender notificationSender;

    @Test
    void registrationSendsAVerificationEmailAndTheTokenVerifiesTheAccount() {
        String email = "verify.success@example.com";
        register(email, PASSWORD);

        String token = notificationSender.lastVerificationTokenFor(email);
        assertThat(token).isNotBlank();

        ResponseEntity<Void> verifyResponse = restTemplate.postForEntity(
                "/api/v1/account/verify-email", new VerifyEmailRequest(token), Void.class);
        assertThat(verifyResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        LoginResponse login = login(email);
        ResponseEntity<UserResponse> me = restTemplate.exchange("/api/v1/users/me", HttpMethod.GET,
                authenticated(login.tokens().accessToken()), UserResponse.class);
        assertThat(me.getBody()).isNotNull();
        assertThat(me.getBody().emailVerified()).isTrue();
    }

    @Test
    void verifyingWithAnUnknownTokenIsRejected() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/account/verify-email", new VerifyEmailRequest("not-a-real-token"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void verifyingTwiceWithTheSameTokenFailsTheSecondTime() {
        String email = "verify.twice@example.com";
        register(email, PASSWORD);
        String token = notificationSender.lastVerificationTokenFor(email);

        restTemplate.postForEntity("/api/v1/account/verify-email", new VerifyEmailRequest(token), Void.class);
        ResponseEntity<String> secondAttempt = restTemplate.postForEntity(
                "/api/v1/account/verify-email", new VerifyEmailRequest(token), String.class);

        assertThat(secondAttempt.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void resendVerificationAlwaysReturnsAcceptedRegardlessOfWhetherEmailExists() {
        String email = "verify.resend@example.com";
        register(email, PASSWORD);

        ResponseEntity<Void> knownEmail = restTemplate.postForEntity(
                "/api/v1/account/resend-verification", new ResendVerificationRequest(email), Void.class);
        ResponseEntity<Void> unknownEmail = restTemplate.postForEntity(
                "/api/v1/account/resend-verification", new ResendVerificationRequest("no.such.user@example.com"),
                Void.class);

        assertThat(knownEmail.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(unknownEmail.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    private void register(String email, String password) {
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, password), UserResponse.class);
    }

    private LoginResponse login(String email) {
        return restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, PASSWORD), LoginResponse.class).getBody();
    }

    private HttpEntity<Void> authenticated(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return new HttpEntity<>(headers);
    }
}
