package io.github.deshenrao.auth0lite.domain;

import java.util.UUID;

public record JwtPrincipal(UUID userId, String email) {
}
