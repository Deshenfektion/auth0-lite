package io.github.deshenrao.auth0lite.mapper;

import io.github.deshenrao.auth0lite.dto.SessionResponse;
import io.github.deshenrao.auth0lite.entity.Session;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class SessionMapper {

    public SessionResponse toResponse(Session session, UUID currentSessionId) {
        return new SessionResponse(
                session.getId(),
                session.getCreatedAt(),
                session.getLastActivityAt(),
                session.getExpiresAt(),
                session.getIpAddress(),
                session.getUserAgent(),
                session.getId().equals(currentSessionId)
        );
    }
}
