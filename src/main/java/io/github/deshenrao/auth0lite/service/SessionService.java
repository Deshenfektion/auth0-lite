package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.SessionProperties;
import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.IssuedRefreshToken;
import io.github.deshenrao.auth0lite.domain.NewSession;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.Session;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.SessionNotFoundException;
import io.github.deshenrao.auth0lite.repository.SessionRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {

    private final SessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogService auditLogService;
    private final SessionProperties properties;
    private final Clock clock;

    public SessionService(
            SessionRepository sessionRepository,
            UserRepository userRepository,
            RefreshTokenService refreshTokenService,
            AuditLogService auditLogService,
            SessionProperties properties,
            Clock clock
    ) {
        this.sessionRepository = sessionRepository;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.auditLogService = auditLogService;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public NewSession startSession(UUID userId, RequestMetadata metadata) {
        UUID sessionId = UUID.randomUUID();
        Instant now = clock.instant();
        Session session = new Session(
                sessionId, userId, now, now.plus(properties.absoluteTtl()),
                metadata.ipAddress(), metadata.userAgent());
        sessionRepository.save(session);

        IssuedRefreshToken refreshToken = refreshTokenService.issueForSession(userId, sessionId);
        return new NewSession(sessionId, refreshToken);
    }

    public List<Session> listActiveSessions(UUID userId) {
        Instant now = clock.instant();
        return sessionRepository.findByUserIdAndRevokedAtIsNull(userId).stream()
                .filter(session -> !session.isExpired(now))
                .toList();
    }

    @Transactional
    public void revokeSession(UUID sessionId, UUID requestingUserId, RequestMetadata metadata) {
        Session session = sessionRepository.findById(sessionId)
                .filter(candidate -> candidate.getUserId().equals(requestingUserId))
                .orElseThrow(SessionNotFoundException::new);

        session.revoke(clock.instant());
        sessionRepository.save(session);
        refreshTokenService.revokeFamily(sessionId);

        auditEmail(requestingUserId).ifPresent(email ->
                auditLogService.record(AuditEventType.SESSION_REVOKED, email, requestingUserId, metadata));
    }

    @Transactional
    public void adminRevokeSession(UUID userId, UUID sessionId, RequestMetadata metadata) {
        Session session = sessionRepository.findById(sessionId)
                .filter(candidate -> candidate.getUserId().equals(userId))
                .orElseThrow(SessionNotFoundException::new);

        session.revoke(clock.instant());
        sessionRepository.save(session);
        refreshTokenService.revokeFamily(sessionId);

        auditEmail(userId).ifPresent(email ->
                auditLogService.record(AuditEventType.SESSION_REVOKED_BY_ADMIN, email, userId, metadata));
    }

    @Transactional
    public void revokeAllSessions(UUID userId, RequestMetadata metadata) {
        Instant now = clock.instant();
        sessionRepository.revokeAllForUser(userId, now);
        refreshTokenService.revokeAllForUser(userId);

        auditEmail(userId).ifPresent(email ->
                auditLogService.record(AuditEventType.ALL_SESSIONS_REVOKED, email, userId, metadata));
    }

    private Optional<String> auditEmail(UUID userId) {
        return userRepository.findById(userId).map(User::getEmail);
    }
}
