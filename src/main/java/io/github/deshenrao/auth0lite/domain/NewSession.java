package io.github.deshenrao.auth0lite.domain;

import java.util.UUID;

public record NewSession(UUID sessionId, IssuedRefreshToken refreshToken) {
}
