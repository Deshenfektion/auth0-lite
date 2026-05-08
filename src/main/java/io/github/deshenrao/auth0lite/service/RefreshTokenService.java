package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.RefreshTokenProperties;
import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.GeneratedToken;
import io.github.deshenrao.auth0lite.domain.IssuedRefreshToken;
import io.github.deshenrao.auth0lite.domain.RefreshResult;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.RefreshToken;
import io.github.deshenrao.auth0lite.entity.Session;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidRefreshTokenException;
import io.github.deshenrao.auth0lite.exception.RefreshTokenReuseDetectedException;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.repository.RefreshTokenRepository;
import io.github.deshenrao.auth0lite.repository.SessionRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import io.github.deshenrao.auth0lite.security.SecureTokenGenerator;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final AuditLogService auditLogService;
    private final SecureTokenGenerator tokenGenerator;
    private final RefreshTokenProperties properties;
    private final Clock clock;
    private final RefreshTokenService self;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            SessionRepository sessionRepository,
            UserRepository userRepository,
            UserMapper userMapper,
            AuditLogService auditLogService,
            SecureTokenGenerator tokenGenerator,
            RefreshTokenProperties properties,
            Clock clock,
            @Lazy RefreshTokenService self
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.sessionRepository = sessionRepository;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.auditLogService = auditLogService;
        this.tokenGenerator = tokenGenerator;
        this.properties = properties;
        this.clock = clock;
        this.self = self;
    }

    @Transactional
    public IssuedRefreshToken issueForSession(UUID userId, UUID sessionId) {
        return issue(userId, sessionId);
    }

    @Transactional
    public RefreshResult rotate(String presentedRawToken, RequestMetadata metadata) {
        RefreshToken existing = refreshTokenRepository.findByTokenHash(tokenGenerator.hash(presentedRawToken))
                .orElseThrow(InvalidRefreshTokenException::new);

        User user = userRepository.findByIdWithRoles(existing.getUserId())
                .orElseThrow(InvalidRefreshTokenException::new);

        Session session = sessionRepository.findById(existing.getFamilyId())
                .orElseThrow(InvalidRefreshTokenException::new);

        if (existing.isRevoked()) {
            self.revokeFamily(existing.getFamilyId());
            auditLogService.record(
                    AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, user.getEmail(), user.getId(), metadata);
            throw new RefreshTokenReuseDetectedException();
        }

        Instant now = clock.instant();
        if (existing.isExpired(now) || !user.isEnabled() || !session.isActive(now)) {
            throw new InvalidRefreshTokenException();
        }

        existing.revoke(now);
        refreshTokenRepository.save(existing);

        session.recordActivity(now, metadata.ipAddress(), metadata.userAgent());
        sessionRepository.save(session);

        IssuedRefreshToken next = issue(user.getId(), existing.getFamilyId());
        auditLogService.record(AuditEventType.REFRESH_TOKEN_ROTATED, user.getEmail(), user.getId(), metadata);

        return new RefreshResult(userMapper.toTokenSubject(user, session.getId()), next);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(UUID familyId) {
        refreshTokenRepository.revokeFamily(familyId, clock.instant());
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        refreshTokenRepository.revokeAllForUser(userId, clock.instant());
    }

    private IssuedRefreshToken issue(UUID userId, UUID familyId) {
        GeneratedToken token = tokenGenerator.generate();

        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.ttl());
        RefreshToken entity = new RefreshToken(userId, familyId, token.hash(), now, expiresAt);
        refreshTokenRepository.save(entity);

        return new IssuedRefreshToken(token.rawValue(), expiresAt);
    }
}
