package io.github.deshenrao.auth0lite.domain;

import java.util.List;
import java.util.UUID;

public record TokenSubject(UUID userId, UUID sessionId, String email, List<String> roles) {
}
