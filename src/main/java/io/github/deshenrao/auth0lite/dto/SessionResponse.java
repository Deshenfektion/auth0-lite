package io.github.deshenrao.auth0lite.dto;

import java.time.Instant;
import java.util.UUID;

public record SessionResponse(
        UUID id,
        Instant createdAt,
        Instant lastActivityAt,
        Instant expiresAt,
        String ipAddress,
        String userAgent,
        boolean current
) {
}
