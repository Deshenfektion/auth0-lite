package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class UserRegistrationIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Test
    void registerCreatesUserWithDefaultRoleAndHashedPassword() {
        RegisterUserRequest request = new RegisterUserRequest("new.user@example.com", "Sup3r$ecurePassw0rd!");

        ResponseEntity<UserResponse> response = restTemplate.postForEntity(
                "/api/v1/auth/register", request, UserResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        UserResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.email()).isEqualTo("new.user@example.com");
        assertThat(body.emailVerified()).isFalse();
        assertThat(body.enabled()).isTrue();
        assertThat(body.roles()).containsExactly("USER");

        assertThat(userRepository.findByEmail("new.user@example.com"))
                .isPresent()
                .get()
                .satisfies(user -> assertThat(user.getPasswordHash()).isNotEqualTo("Sup3r$ecurePassw0rd!"));
    }

    @Test
    void registerNormalizesEmailToLowercase() {
        RegisterUserRequest request = new RegisterUserRequest("Mixed.Case@Example.com", "Sup3r$ecurePassw0rd!");

        ResponseEntity<UserResponse> response = restTemplate.postForEntity(
                "/api/v1/auth/register", request, UserResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().email()).isEqualTo("mixed.case@example.com");
    }

    @Test
    void registerRejectsDuplicateEmail() {
        RegisterUserRequest request = new RegisterUserRequest("duplicate@example.com", "Sup3r$ecurePassw0rd!");
        restTemplate.postForEntity("/api/v1/auth/register", request, UserResponse.class);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/auth/register", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).contains("already exists");
    }

    @Test
    void registerRejectsWeakPassword() {
        RegisterUserRequest request = new RegisterUserRequest("weak.password@example.com", "short");

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/api/v1/auth/register", request, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
