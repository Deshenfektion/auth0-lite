package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.ForgotPasswordRequest;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.ResetPasswordRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({TestcontainersConfiguration.class, FakeNotificationSenderConfiguration.class})
class PasswordResetIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";
    private static final String NEW_PASSWORD = "Ev3nStr0ngerPassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private CapturingNotificationSender notificationSender;

    @Test
    void forgotPasswordAlwaysReturnsAcceptedRegardlessOfWhetherEmailExists() {
        String email = "reset.enumeration@example.com";
        register(email, PASSWORD);

        ResponseEntity<Void> knownEmail = restTemplate.postForEntity(
                "/api/v1/account/forgot-password", new ForgotPasswordRequest(email), Void.class);
        ResponseEntity<Void> unknownEmail = restTemplate.postForEntity(
                "/api/v1/account/forgot-password", new ForgotPasswordRequest("no.such.user@example.com"),
                Void.class);

        assertThat(knownEmail.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(unknownEmail.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    @Test
    void resettingPasswordChangesCredentialsAndRevokesAllExistingSessions() {
        String email = "reset.success@example.com";
        register(email, PASSWORD);
        LoginResponse originalLogin = login(email, PASSWORD);

        restTemplate.postForEntity("/api/v1/account/forgot-password", new ForgotPasswordRequest(email), Void.class);
        String resetToken = notificationSender.lastPasswordResetTokenFor(email);
        assertThat(resetToken).isNotBlank();

        ResponseEntity<Void> resetResponse = restTemplate.postForEntity(
                "/api/v1/account/reset-password", new ResetPasswordRequest(resetToken, NEW_PASSWORD), Void.class);
        assertThat(resetResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> oldRefreshAttempt = restTemplate.postForEntity(
                "/api/v1/auth/refresh", new RefreshTokenRequest(originalLogin.tokens().refreshToken()),
                String.class);
        assertThat(oldRefreshAttempt.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<String> loginWithOldPassword = restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, PASSWORD), String.class);
        assertThat(loginWithOldPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<LoginResponse> loginWithNewPassword = restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, NEW_PASSWORD), LoginResponse.class);
        assertThat(loginWithNewPassword.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void resetTokenCannotBeReusedAfterASuccessfulReset() {
        String email = "reset.reuse@example.com";
        register(email, PASSWORD);
        restTemplate.postForEntity("/api/v1/account/forgot-password", new ForgotPasswordRequest(email), Void.class);
        String resetToken = notificationSender.lastPasswordResetTokenFor(email);

        restTemplate.postForEntity(
                "/api/v1/account/reset-password", new ResetPasswordRequest(resetToken, NEW_PASSWORD), Void.class);
        ResponseEntity<String> secondAttempt = restTemplate.postForEntity(
                "/api/v1/account/reset-password",
                new ResetPasswordRequest(resetToken, "AnotherStr0ngPassword!"), String.class);

        assertThat(secondAttempt.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void resetPasswordRejectsAnUnknownToken() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/account/reset-password", new ResetPasswordRequest("garbage-token", NEW_PASSWORD),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private void register(String email, String password) {
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, password), UserResponse.class);
    }

    private LoginResponse login(String email, String password) {
        return restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, password), LoginResponse.class).getBody();
    }
}
