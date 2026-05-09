package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.ChangePasswordRequest;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
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
@Import(TestcontainersConfiguration.class)
class ChangePasswordIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";
    private static final String NEW_PASSWORD = "Ev3nStr0ngerPassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void changingPasswordKeepsTheCurrentSessionAliveButRevokesOtherSessions() {
        String email = "change.password@example.com";
        register(email, PASSWORD);
        LoginResponse deviceA = login(email, PASSWORD);
        LoginResponse deviceB = login(email, PASSWORD);

        ResponseEntity<Void> changeResponse = restTemplate.exchange(
                "/api/v1/account/change-password", HttpMethod.POST,
                authenticatedBody(deviceA.tokens().accessToken(), new ChangePasswordRequest(PASSWORD, NEW_PASSWORD)),
                Void.class);
        assertThat(changeResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> deviceARefresh = refresh(deviceA.tokens().refreshToken());
        assertThat(deviceARefresh.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> deviceBRefresh = refresh(deviceB.tokens().refreshToken());
        assertThat(deviceBRefresh.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<LoginResponse> loginWithNewPassword = restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, NEW_PASSWORD), LoginResponse.class);
        assertThat(loginWithNewPassword.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void changePasswordRejectsAnIncorrectCurrentPassword() {
        String email = "change.password.wrong@example.com";
        register(email, PASSWORD);
        LoginResponse login = login(email, PASSWORD);

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/account/change-password", HttpMethod.POST,
                authenticatedBody(login.tokens().accessToken(),
                        new ChangePasswordRequest("TotallyWrongPassword1!", NEW_PASSWORD)),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void changePasswordRequiresAuthentication() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/account/change-password", new ChangePasswordRequest(PASSWORD, NEW_PASSWORD), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private ResponseEntity<String> refresh(String refreshToken) {
        return restTemplate.postForEntity(
                "/api/v1/auth/refresh", new RefreshTokenRequest(refreshToken), String.class);
    }

    private void register(String email, String password) {
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, password), UserResponse.class);
    }

    private LoginResponse login(String email, String password) {
        return restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, password), LoginResponse.class).getBody();
    }

    private <T> HttpEntity<T> authenticatedBody(String accessToken, T body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return new HttpEntity<>(body, headers);
    }
}
