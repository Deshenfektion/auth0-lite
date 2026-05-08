package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.domain.GeneratedToken;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class SecureTokenGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    public GeneratedToken generate() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String rawValue = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return new GeneratedToken(rawValue, hash(rawValue));
    }

    public String hash(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }
}
