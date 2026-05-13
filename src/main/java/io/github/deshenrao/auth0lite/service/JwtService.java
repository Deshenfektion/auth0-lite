package io.github.deshenrao.auth0lite.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.deshenrao.auth0lite.config.JwtProperties;
import io.github.deshenrao.auth0lite.domain.TokenSubject;
import io.github.deshenrao.auth0lite.exception.InvalidTokenException;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtProperties properties;
    private final Clock clock;
    private final RSAKey signingKey;
    private final RSASSASigner signer;
    private final RSASSAVerifier verifier;

    public JwtService(JwtProperties properties, RSAKey signingKey, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        this.signingKey = signingKey;
        try {
            this.signer = new RSASSASigner(signingKey);
            this.verifier = new RSASSAVerifier(signingKey);
        } catch (JOSEException exception) {
            throw new IllegalStateException("The configured JWT signing key is not usable for RS256", exception);
        }
    }

    public String generateAccessToken(TokenSubject subject) {
        Instant now = clock.instant();
        Instant expiry = now.plus(properties.accessTokenTtl());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .audience(properties.audience())
                .subject(subject.userId().toString())
                .claim("sid", subject.sessionId().toString())
                .claim("email", subject.email())
                .claim("roles", subject.roles())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiry))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        try {
            signedJwt.sign(signer);
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to sign access token", exception);
        }
        return signedJwt.serialize();
    }

    public JWTClaimsSet parseAndValidate(String token) {
        SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(token);
        } catch (ParseException exception) {
            throw new InvalidTokenException("Token is malformed");
        }

        boolean signatureValid;
        try {
            signatureValid = signedJwt.verify(verifier);
        } catch (JOSEException exception) {
            throw new InvalidTokenException("Token signature could not be verified");
        }

        if (!signatureValid) {
            throw new InvalidTokenException("Token signature is invalid");
        }

        JWTClaimsSet claims;
        try {
            claims = signedJwt.getJWTClaimsSet();
        } catch (ParseException exception) {
            throw new InvalidTokenException("Token claims are malformed");
        }

        if (claims.getExpirationTime() == null || claims.getExpirationTime().before(Date.from(clock.instant()))) {
            throw new InvalidTokenException("Token has expired");
        }

        if (!properties.issuer().equals(claims.getIssuer())) {
            throw new InvalidTokenException("Token issuer is not trusted");
        }

        if (claims.getAudience() == null || !claims.getAudience().contains(properties.audience())) {
            throw new InvalidTokenException("Token audience is not valid for this service");
        }

        return claims;
    }
}
