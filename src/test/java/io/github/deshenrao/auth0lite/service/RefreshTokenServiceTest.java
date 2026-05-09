package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.RefreshTokenProperties;
import io.github.deshenrao.auth0lite.domain.RefreshResult;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.entity.RefreshToken;
import io.github.deshenrao.auth0lite.entity.Role;
import io.github.deshenrao.auth0lite.entity.Session;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidRefreshTokenException;
import io.github.deshenrao.auth0lite.exception.RefreshTokenReuseDetectedException;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.repository.RefreshTokenRepository;
import io.github.deshenrao.auth0lite.repository.SessionRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import io.github.deshenrao.auth0lite.security.SecureTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private SessionRepository sessionRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditLogService auditLogService;

    private final UserMapper userMapper = new UserMapper();
    private final SecureTokenGenerator tokenGenerator = new SecureTokenGenerator();
    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final RefreshTokenProperties properties = new RefreshTokenProperties(Duration.ofDays(30));

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(
                refreshTokenRepository, sessionRepository, userRepository, userMapper, auditLogService,
                tokenGenerator, properties, clock, null);
        ReflectionTestUtils.setField(refreshTokenService, "self", refreshTokenService);
    }

    @Test
    void rotateRejectsUnknownToken() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.rotate("does-not-exist", metadata()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rotateRejectsExpiredToken() {
        User user = testUser();
        UUID familyId = UUID.randomUUID();
        RefreshToken expired = new RefreshToken(user.getId(), familyId, "hash",
                clock.instant().minus(Duration.ofDays(31)), clock.instant().minus(Duration.ofDays(1)));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(expired));
        when(userRepository.findByIdWithRoles(user.getId())).thenReturn(Optional.of(user));
        when(sessionRepository.findById(familyId)).thenReturn(Optional.of(activeSession(familyId, user.getId())));

        assertThatThrownBy(() -> refreshTokenService.rotate("presented-token", metadata()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rotateDetectsReuseOfAnAlreadyRevokedTokenAndRevokesTheWholeFamily() {
        User user = testUser();
        UUID familyId = UUID.randomUUID();
        RefreshToken alreadyRevoked = new RefreshToken(user.getId(), familyId, "hash",
                clock.instant().minus(Duration.ofMinutes(5)), clock.instant().plus(Duration.ofDays(29)));
        alreadyRevoked.revoke(clock.instant().minus(Duration.ofMinutes(1)));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(alreadyRevoked));
        when(userRepository.findByIdWithRoles(user.getId())).thenReturn(Optional.of(user));
        when(sessionRepository.findById(familyId)).thenReturn(Optional.of(activeSession(familyId, user.getId())));

        assertThatThrownBy(() -> refreshTokenService.rotate("presented-token", metadata()))
                .isInstanceOf(RefreshTokenReuseDetectedException.class);

        verify(refreshTokenRepository).revokeFamily(eq(familyId), any());
    }

    @Test
    void rotateRevokesOldTokenAndIssuesANewOneInTheSameFamilyWhenValid() {
        User user = testUser();
        UUID familyId = UUID.randomUUID();
        RefreshToken valid = new RefreshToken(user.getId(), familyId, "hash",
                clock.instant().minus(Duration.ofMinutes(5)), clock.instant().plus(Duration.ofDays(29)));
        Session session = activeSession(familyId, user.getId());

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(valid));
        when(userRepository.findByIdWithRoles(user.getId())).thenReturn(Optional.of(user));
        when(sessionRepository.findById(familyId)).thenReturn(Optional.of(session));

        RefreshResult result = refreshTokenService.rotate("presented-token", metadata());

        assertThat(valid.isRevoked()).isTrue();
        assertThat(result.subject().userId()).isEqualTo(user.getId());
        assertThat(result.subject().sessionId()).isEqualTo(familyId);
        assertThat(result.refreshToken().rawToken()).isNotBlank();
        verify(refreshTokenRepository, times(2)).save(any());
        verify(sessionRepository).save(session);
    }

    @Test
    void rotateRejectsTokenBelongingToADisabledUser() {
        User user = testUser();
        ReflectionTestUtils.setField(user, "enabled", false);
        UUID familyId = UUID.randomUUID();
        RefreshToken valid = new RefreshToken(user.getId(), familyId, "hash",
                clock.instant().minus(Duration.ofMinutes(5)), clock.instant().plus(Duration.ofDays(29)));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(valid));
        when(userRepository.findByIdWithRoles(user.getId())).thenReturn(Optional.of(user));
        when(sessionRepository.findById(familyId)).thenReturn(Optional.of(activeSession(familyId, user.getId())));

        assertThatThrownBy(() -> refreshTokenService.rotate("presented-token", metadata()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rotateRejectsTokenWhenItsSessionHasBeenRevoked() {
        User user = testUser();
        UUID familyId = UUID.randomUUID();
        RefreshToken valid = new RefreshToken(user.getId(), familyId, "hash",
                clock.instant().minus(Duration.ofMinutes(5)), clock.instant().plus(Duration.ofDays(29)));
        Session revokedSession = activeSession(familyId, user.getId());
        revokedSession.revoke(clock.instant().minus(Duration.ofMinutes(1)));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(valid));
        when(userRepository.findByIdWithRoles(user.getId())).thenReturn(Optional.of(user));
        when(sessionRepository.findById(familyId)).thenReturn(Optional.of(revokedSession));

        assertThatThrownBy(() -> refreshTokenService.rotate("presented-token", metadata()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    private User testUser() {
        User user = new User("rotation.test@example.com", "hash");
        user.assignRole(new Role(RoleName.USER));
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }

    private Session activeSession(UUID sessionId, UUID userId) {
        return new Session(sessionId, userId, clock.instant().minus(Duration.ofDays(1)),
                clock.instant().plus(Duration.ofDays(89)), "127.0.0.1", "junit");
    }

    private RequestMetadata metadata() {
        return new RequestMetadata("127.0.0.1", "junit");
    }
}
