package io.github.deshenrao.auth0lite;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
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
@Import(TestcontainersConfiguration.class)
class JwksIntegrationTest {

    private static final String PASSWORD = "Sup3r$ecurePassw0rd!";

    @Autowired
    private TestRestTemplate restTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void jwksEndpointExposesOnlyThePublicKeyComponents() throws Exception {
        ResponseEntity<String> response = restTemplate.getForEntity("/.well-known/jwks.json", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        JsonNode key = objectMapper.readTree(response.getBody()).get("keys").get(0);
        assertThat(key.get("kty").asText()).isEqualTo("RSA");
        assertThat(key.get("use").asText()).isEqualTo("sig");
        assertThat(key.has("n")).isTrue();
        assertThat(key.has("e")).isTrue();
        assertThat(key.has("d")).as("private exponent must never be published").isFalse();
        assertThat(key.has("p")).as("private prime factor must never be published").isFalse();
        assertThat(key.has("q")).as("private prime factor must never be published").isFalse();
    }

    @Test
    void anAccessTokenCanBeVerifiedByAnIndependentPartyUsingOnlyThePublishedJwks() throws Exception {
        String email = "jwks.independent.verify@example.com";
        restTemplate.postForEntity(
                "/api/v1/auth/register", new RegisterUserRequest(email, PASSWORD), UserResponse.class);
        LoginResponse login = restTemplate.postForEntity(
                "/api/v1/auth/login", new LoginRequest(email, PASSWORD), LoginResponse.class).getBody();
        String accessToken = login.tokens().accessToken();

        String jwksJson = restTemplate.getForEntity("/.well-known/jwks.json", String.class).getBody();
        JWKSet jwkSet = JWKSet.parse(jwksJson);

        SignedJWT signedJwt = SignedJWT.parse(accessToken);
        String keyId = signedJwt.getHeader().getKeyID();
        RSAKey publicOnlyKey = (RSAKey) jwkSet.getKeyByKeyId(keyId);

        assertThat(publicOnlyKey).isNotNull();
        assertThat(publicOnlyKey.isPrivate())
                .as("the JWKS-published key must not carry private key material")
                .isFalse();

        boolean verified = signedJwt.verify(new RSASSAVerifier(publicOnlyKey));

        assertThat(verified).isTrue();
    }
}
