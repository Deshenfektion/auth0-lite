package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.SessionResponse;
import io.github.deshenrao.auth0lite.dto.TokenResponse;
import io.github.deshenrao.auth0lite.dto.UserResponse;
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
class SessionManagementIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void loginCreatesASessionVisibleInTheSessionListAsCurrent() {
        String email = "session.single@example.com";
        register(email, PASSWORD);
        LoginResponse login = login(email);

        List<SessionResponse> sessions = listSessions(login.tokens().accessToken());

        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).current()).isTrue();
    }

    @Test
    void loggingInFromTwoDevicesCreatesTwoIndependentSessions() {
        String email = "session.multi.device@example.com";
        register(email, PASSWORD);
        LoginResponse phone = login(email);
        LoginResponse laptop = login(email);

        List<SessionResponse> fromPhone = listSessions(phone.tokens().accessToken());
        assertThat(fromPhone).hasSize(2);
        assertThat(fromPhone.stream().filter(SessionResponse::current)).hasSize(1);

        List<SessionResponse> fromLaptop = listSessions(laptop.tokens().accessToken());
        assertThat(fromLaptop).hasSize(2);
        assertThat(fromLaptop.stream().filter(SessionResponse::current)).hasSize(1);
    }

    @Test
    void revokingOneSessionDisablesOnlyThatSessionsRefreshToken() {
        String email = "session.revoke.one@example.com";
        register(email, PASSWORD);
        LoginResponse deviceA = login(email);
        LoginResponse deviceB = login(email);

        UUID deviceASessionId = listSessions(deviceA.tokens().accessToken()).stream()
                .filter(SessionResponse::current)
                .findFirst()
                .orElseThrow()
                .id();

        ResponseEntity<Void> revokeResponse = restTemplate.exchange(
                "/api/v1/sessions/" + deviceASessionId, HttpMethod.DELETE,
                authenticated(deviceA.tokens().accessToken()), Void.class);
        assertThat(revokeResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> deviceARefresh = refresh(deviceA.tokens().refreshToken(), String.class);
        assertThat(deviceARefresh.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<TokenResponse> deviceBRefresh = refresh(deviceB.tokens().refreshToken(), TokenResponse.class);
        assertThat(deviceBRefresh.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void cannotRevokeAnotherUsersSession() {
        register("session.victim@example.com", PASSWORD);
        LoginResponse victim = login("session.victim@example.com");
        UUID victimSessionId = listSessions(victim.tokens().accessToken()).get(0).id();

        register("session.attacker@example.com", PASSWORD);
        LoginResponse attacker = login("session.attacker@example.com");

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/v1/sessions/" + victimSessionId, HttpMethod.DELETE,
                authenticated(attacker.tokens().accessToken()), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<TokenResponse> stillWorks = refresh(victim.tokens().refreshToken(), TokenResponse.class);
        assertThat(stillWorks.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void logoutRevokesTheCallersOwnCurrentSession() {
        String email = "session.logout@example.com";
        register(email, PASSWORD);
        LoginResponse login = login(email);

        ResponseEntity<Void> logoutResponse = restTemplate.exchange(
                "/api/v1/auth/logout", HttpMethod.POST, authenticated(login.tokens().accessToken()), Void.class);
        assertThat(logoutResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> refreshAfterLogout = refresh(login.tokens().refreshToken(), String.class);
        assertThat(refreshAfterLogout.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void revokingAllSessionsLogsOutEveryDevice() {
        String email = "session.logout.everywhere@example.com";
        register(email, PASSWORD);
        LoginResponse deviceA = login(email);
        LoginResponse deviceB = login(email);

        ResponseEntity<Void> response = restTemplate.exchange(
                "/api/v1/sessions", HttpMethod.DELETE, authenticated(deviceA.tokens().accessToken()), Void.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        assertThat(refresh(deviceA.tokens().refreshToken(), String.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh(deviceB.tokens().refreshToken(), String.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private void register(String email, String password) {
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, password), UserResponse.class);
    }

    private LoginResponse login(String email) {
        return restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, PASSWORD), LoginResponse.class).getBody();
    }

    private List<SessionResponse> listSessions(String accessToken) {
        ResponseEntity<List<SessionResponse>> response = restTemplate.exchange(
                "/api/v1/sessions", HttpMethod.GET, authenticated(accessToken),
                new ParameterizedTypeReference<List<SessionResponse>>() {
                });
        return response.getBody();
    }

    private <T> ResponseEntity<T> refresh(String refreshToken, Class<T> responseType) {
        return restTemplate.postForEntity(
                "/api/v1/auth/refresh", new RefreshTokenRequest(refreshToken), responseType);
    }

    private HttpEntity<Void> authenticated(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return new HttpEntity<>(headers);
    }
}
