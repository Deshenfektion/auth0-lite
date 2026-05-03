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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class JwtProtectedEndpointIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void meEndpointReturnsAuthenticatedUserWhenGivenAValidAccessToken() {
        String email = "jwt.flow@example.com";
        register(email, PASSWORD);
        String accessToken = login(email, PASSWORD).tokens().accessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        ResponseEntity<UserResponse> response = restTemplate.exchange(
                "/api/v1/users/me", HttpMethod.GET, new HttpEntity<>(headers), UserResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().email()).isEqualTo(email);
        assertThat(response.getBody().roles()).containsExactly("USER");
    }

    @Test
    void meEndpointRejectsRequestWithNoAuthorizationHeader() {
        ResponseEntity<String> response = restTemplate.getForEntity("/api/v1/users/me", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void meEndpointRejectsMalformedToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth("not-a-real-jwt");
        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/users/me", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
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
