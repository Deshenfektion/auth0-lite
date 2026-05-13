package io.github.deshenrao.auth0lite.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import io.github.deshenrao.auth0lite.config.JwtProperties;
import io.github.deshenrao.auth0lite.domain.TokenSubject;
import io.github.deshenrao.auth0lite.exception.InvalidTokenException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final RSAKey SIGNING_KEY = generateTestKey();

    private final JwtProperties properties = new JwtProperties(
            "auth0-lite-test-issuer",
            "auth0-lite-test-audience",
            Duration.ofMinutes(15)
    );

    @Test
    void generatesAndValidatesTokenWithExpectedClaims() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService jwtService = new JwtService(properties, SIGNING_KEY, clock);
        TokenSubject subject = new TokenSubject(
                UUID.randomUUID(), UUID.randomUUID(), "claims.test@example.com", List.of("USER"));

        String token = jwtService.generateAccessToken(subject);
        JWTClaimsSet claims = jwtService.parseAndValidate(token);

        assertThat(claims.getSubject()).isEqualTo(subject.userId().toString());
        assertThat(claims.getIssuer()).isEqualTo(properties.issuer());
        assertThat(claims.getAudience()).containsExactly(properties.audience());
        assertThat(claims.getStringClaim("sid")).isEqualTo(subject.sessionId().toString());
        assertThat(claims.getStringClaim("email")).isEqualTo(subject.email());
        assertThat(claims.getStringListClaim("roles")).containsExactly("USER");
    }

    @Test
    void rejectsExpiredToken() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        JwtService issuingService = new JwtService(properties, SIGNING_KEY, Clock.fixed(issuedAt, ZoneOffset.UTC));
        TokenSubject subject = new TokenSubject(
                UUID.randomUUID(), UUID.randomUUID(), "expired@example.com", List.of("USER"));
        String token = issuingService.generateAccessToken(subject);

        Clock afterExpiry = Clock.fixed(issuedAt.plus(Duration.ofMinutes(16)), ZoneOffset.UTC);
        JwtService validatingService = new JwtService(properties, SIGNING_KEY, afterExpiry);

        assertThatThrownBy(() -> validatingService.parseAndValidate(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void rejectsTokenSignedWithADifferentIssuer() {
        JwtProperties otherIssuerProperties = new JwtProperties(
                "some-other-issuer", properties.audience(), properties.accessTokenTtl());
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService issuingService = new JwtService(otherIssuerProperties, SIGNING_KEY, clock);
        JwtService validatingService = new JwtService(properties, SIGNING_KEY, clock);

        TokenSubject subject = new TokenSubject(
                UUID.randomUUID(), UUID.randomUUID(), "wrong.issuer@example.com", List.of("USER"));
        String token = issuingService.generateAccessToken(subject);

        assertThatThrownBy(() -> validatingService.parseAndValidate(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void rejectsTokenSignedWithADifferentKey() throws JOSEException {
        RSAKey otherKey = generateTestKey();
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService issuingService = new JwtService(properties, otherKey, clock);
        JwtService validatingService = new JwtService(properties, SIGNING_KEY, clock);

        TokenSubject subject = new TokenSubject(
                UUID.randomUUID(), UUID.randomUUID(), "wrong.key@example.com", List.of("USER"));
        String token = issuingService.generateAccessToken(subject);

        assertThatThrownBy(() -> validatingService.parseAndValidate(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void rejectsTamperedSignature() {
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService jwtService = new JwtService(properties, SIGNING_KEY, clock);
        TokenSubject subject = new TokenSubject(
                UUID.randomUUID(), UUID.randomUUID(), "tampered@example.com", List.of("USER"));
        String token = jwtService.generateAccessToken(subject);

        int signatureStart = token.lastIndexOf('.') + 1;
        int tamperIndex = signatureStart + (token.length() - signatureStart) / 2;
        char originalChar = token.charAt(tamperIndex);
        char replacementChar = originalChar == 'A' ? 'B' : 'A';
        String tamperedToken = token.substring(0, tamperIndex) + replacementChar + token.substring(tamperIndex + 1);

        assertThatThrownBy(() -> jwtService.parseAndValidate(tamperedToken))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void rejectsMalformedToken() {
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JwtService jwtService = new JwtService(properties, SIGNING_KEY, clock);

        assertThatThrownBy(() -> jwtService.parseAndValidate("not-a-jwt"))
                .isInstanceOf(InvalidTokenException.class);
    }

    private static RSAKey generateTestKey() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyIDFromThumbprint(true)
                    .generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to generate a test RSA key", exception);
        }
    }
}
