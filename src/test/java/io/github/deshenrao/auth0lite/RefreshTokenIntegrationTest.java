package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.TokenResponse;
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
class RefreshTokenIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void refreshIssuesNewTokenPairAndTheNewAccessTokenWorks() {
        String email = "refresh.happy@example.com";
        register(email, PASSWORD);
        TokenResponse original = login(email).tokens();

        ResponseEntity<TokenResponse> refreshed = refresh(original.refreshToken());

        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        TokenResponse newTokens = refreshed.getBody();
        assertThat(newTokens).isNotNull();
        assertThat(newTokens.accessToken()).isNotEqualTo(original.accessToken());
        assertThat(newTokens.refreshToken()).isNotEqualTo(original.refreshToken());

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(newTokens.accessToken());
        ResponseEntity<UserResponse> meResponse = restTemplate.exchange(
                "/api/v1/users/me", HttpMethod.GET, new HttpEntity<>(headers), UserResponse.class);
        assertThat(meResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(meResponse.getBody()).isNotNull();
        assertThat(meResponse.getBody().email()).isEqualTo(email);
    }

    @Test
    void reusingARotatedAwayRefreshTokenIsRejectedAndRevokesTheWholeFamily() {
        String email = "refresh.theft@example.com";
        register(email, PASSWORD);
        TokenResponse original = login(email).tokens();

        ResponseEntity<TokenResponse> firstRotation = refresh(original.refreshToken());
        assertThat(firstRotation.getStatusCode()).isEqualTo(HttpStatus.OK);
        String rotatedRefreshToken = firstRotation.getBody().refreshToken();

        ResponseEntity<String> reuseAttempt = refresh(original.refreshToken(), String.class);
        assertThat(reuseAttempt.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<String> legitimateFollowUp = refresh(rotatedRefreshToken, String.class);
        assertThat(legitimateFollowUp.getStatusCode())
                .as("the whole family, including the legitimately-rotated token, must be dead after reuse is detected")
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void refreshRejectsUnknownToken() {
        ResponseEntity<String> response = refresh("this-token-was-never-issued", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private void register(String email, String password) {
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, password), UserResponse.class);
    }

    private LoginResponse login(String email) {
        return restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, PASSWORD), LoginResponse.class).getBody();
    }

    private ResponseEntity<TokenResponse> refresh(String refreshToken) {
        return refresh(refreshToken, TokenResponse.class);
    }

    private <T> ResponseEntity<T> refresh(String refreshToken, Class<T> responseType) {
        return restTemplate.postForEntity(
                "/api/v1/auth/refresh", new RefreshTokenRequest(refreshToken), responseType);
    }
}
