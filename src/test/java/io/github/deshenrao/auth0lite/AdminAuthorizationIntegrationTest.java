package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.SessionResponse;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.Role;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.repository.RoleRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
class AdminAuthorizationIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void regularUserIsForbiddenFromAdminEndpoints() {
        String email = "admin.rejection@example.com";
        register(email, PASSWORD);
        LoginResponse regularUser = login(email);

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/admin/users/" + UUID.randomUUID() + "/sessions", HttpMethod.GET,
                authenticated(regularUser.tokens().accessToken()), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void adminCanListAndRevokeAnotherUsersSessionViaRoleAndPermissionChecks() {
        String targetEmail = "admin.target@example.com";
        register(targetEmail, PASSWORD);
        LoginResponse target = login(targetEmail);
        UUID targetUserId = userRepository.findByEmail(targetEmail).orElseThrow().getId();

        String adminEmail = "admin.actor@example.com";
        register(adminEmail, PASSWORD);
        promoteToAdmin(adminEmail);
        LoginResponse admin = login(adminEmail);

        ResponseEntity<List<SessionResponse>> listResponse = restTemplate.exchange(
                "/api/v1/admin/users/" + targetUserId + "/sessions", HttpMethod.GET,
                authenticated(admin.tokens().accessToken()),
                new ParameterizedTypeReference<List<SessionResponse>>() {
                });
        assertThat(listResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(listResponse.getBody()).hasSize(1);
        UUID targetSessionId = listResponse.getBody().get(0).id();

        ResponseEntity<Void> revokeResponse = restTemplate.exchange(
                "/api/v1/admin/users/" + targetUserId + "/sessions/" + targetSessionId, HttpMethod.DELETE,
                authenticated(admin.tokens().accessToken()), Void.class);
        assertThat(revokeResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> targetRefreshAfterRevoke = restTemplate.postForEntity(
                "/api/v1/auth/refresh", new RefreshTokenRequest(target.tokens().refreshToken()), String.class);
        assertThat(targetRefreshAfterRevoke.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void adminCannotRevokeASessionUnderTheWrongUserIdInThePath() {
        String targetEmail = "admin.mismatch.target@example.com";
        register(targetEmail, PASSWORD);
        UUID targetUserId = userRepository.findByEmail(targetEmail).orElseThrow().getId();
        UUID targetSessionId = listSessionsAsSelf(targetEmail).get(0).id();

        String adminEmail = "admin.mismatch.actor@example.com";
        register(adminEmail, PASSWORD);
        promoteToAdmin(adminEmail);
        LoginResponse admin = login(adminEmail);

        UUID wrongUserId = UUID.randomUUID();
        assertThat(wrongUserId).isNotEqualTo(targetUserId);

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/admin/users/" + wrongUserId + "/sessions/" + targetSessionId, HttpMethod.DELETE,
                authenticated(admin.tokens().accessToken()), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private List<SessionResponse> listSessionsAsSelf(String email) {
        LoginResponse loginResponse = login(email);
        ResponseEntity<List<SessionResponse>> response = restTemplate.exchange(
                "/api/v1/sessions", HttpMethod.GET, authenticated(loginResponse.tokens().accessToken()),
                new ParameterizedTypeReference<List<SessionResponse>>() {
                });
        return response.getBody();
    }

    private void promoteToAdmin(String email) {
        User user = userRepository.findByEmailWithRoles(email).orElseThrow();
        Role adminRole = roleRepository.findByName(RoleName.ADMIN).orElseThrow();
        user.assignRole(adminRole);
        userRepository.save(user);
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
