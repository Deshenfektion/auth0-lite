package io.github.deshenrao.auth0lite.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        boolean emailVerified,
        boolean enabled,
        Set<String> roles,
        Instant createdAt
) {
}
