package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.RefreshTokenProperties;
import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.IssuedRefreshToken;
import io.github.deshenrao.auth0lite.domain.RefreshResult;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.RefreshToken;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidRefreshTokenException;
import io.github.deshenrao.auth0lite.exception.RefreshTokenReuseDetectedException;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.repository.RefreshTokenRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final AuditLogService auditLogService;
    private final RefreshTokenProperties properties;
    private final Clock clock;
    private final RefreshTokenService self;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            UserMapper userMapper,
            AuditLogService auditLogService,
            RefreshTokenProperties properties,
            Clock clock,
            @Lazy RefreshTokenService self
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.auditLogService = auditLogService;
        this.properties = properties;
        this.clock = clock;
        this.self = self;
    }

    @Transactional
    public IssuedRefreshToken issueForNewLogin(UUID userId) {
        return issue(userId, UUID.randomUUID());
    }

    @Transactional
    public RefreshResult rotate(String presentedRawToken, RequestMetadata metadata) {
        RefreshToken existing = refreshTokenRepository.findByTokenHash(hash(presentedRawToken))
                .orElseThrow(InvalidRefreshTokenException::new);

        User user = userRepository.findByIdWithRoles(existing.getUserId())
                .orElseThrow(InvalidRefreshTokenException::new);

        if (existing.isRevoked()) {
            self.revokeFamily(existing.getFamilyId());
            auditLogService.record(
                    AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, user.getEmail(), user.getId(), metadata);
            throw new RefreshTokenReuseDetectedException();
        }

        if (existing.isExpired(clock.instant()) || !user.isEnabled()) {
            throw new InvalidRefreshTokenException();
        }

        existing.revoke(clock.instant());
        refreshTokenRepository.save(existing);

        IssuedRefreshToken next = issue(user.getId(), existing.getFamilyId());
        auditLogService.record(AuditEventType.REFRESH_TOKEN_ROTATED, user.getEmail(), user.getId(), metadata);

        return new RefreshResult(userMapper.toTokenSubject(user), next);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(UUID familyId) {
        refreshTokenRepository.revokeFamily(familyId, clock.instant());
    }

    private IssuedRefreshToken issue(UUID userId, UUID familyId) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.ttl());
        RefreshToken entity = new RefreshToken(userId, familyId, hash(rawToken), now, expiresAt);
        refreshTokenRepository.save(entity);

        return new IssuedRefreshToken(rawToken, expiresAt);
    }

    private String hash(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }
}
