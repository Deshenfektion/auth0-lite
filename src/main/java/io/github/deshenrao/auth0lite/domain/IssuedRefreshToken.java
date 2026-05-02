package io.github.deshenrao.auth0lite.domain;

import java.time.Instant;

public record IssuedRefreshToken(String rawToken, Instant expiresAt) {
}
