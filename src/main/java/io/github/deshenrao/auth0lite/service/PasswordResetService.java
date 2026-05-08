package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.PasswordResetProperties;
import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.GeneratedToken;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.PasswordResetToken;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidPasswordResetTokenException;
import io.github.deshenrao.auth0lite.notification.NotificationSender;
import io.github.deshenrao.auth0lite.repository.PasswordResetTokenRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import io.github.deshenrao.auth0lite.security.SecureTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final SecureTokenGenerator tokenGenerator;
    private final NotificationSender notificationSender;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final AuditLogService auditLogService;
    private final PasswordResetProperties properties;
    private final Clock clock;

    public PasswordResetService(
            PasswordResetTokenRepository tokenRepository,
            UserRepository userRepository,
            SecureTokenGenerator tokenGenerator,
            NotificationSender notificationSender,
            PasswordEncoder passwordEncoder,
            SessionService sessionService,
            AuditLogService auditLogService,
            PasswordResetProperties properties,
            Clock clock
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.tokenGenerator = tokenGenerator;
        this.notificationSender = notificationSender;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.auditLogService = auditLogService;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public void requestPasswordReset(String email) {
        String normalizedEmail = email.strip().toLowerCase();
        GeneratedToken token = tokenGenerator.generate();

        userRepository.findByEmail(normalizedEmail).ifPresent(user -> {
            Instant now = clock.instant();
            PasswordResetToken entity = new PasswordResetToken(
                    user.getId(), token.hash(), now, now.plus(properties.ttl()));
            tokenRepository.save(entity);

            try {
                notificationSender.sendPasswordReset(user.getEmail(), token.rawValue());
            } catch (RuntimeException exception) {
                log.error("Failed to send password reset email to {}", user.getEmail(), exception);
            }
        });
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword, RequestMetadata metadata) {
        PasswordResetToken token = tokenRepository.findByTokenHash(tokenGenerator.hash(rawToken))
                .orElseThrow(InvalidPasswordResetTokenException::new);

        Instant now = clock.instant();
        if (token.isUsed() || token.isExpired(now)) {
            throw new InvalidPasswordResetTokenException();
        }

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(InvalidPasswordResetTokenException::new);

        token.markUsed(now);
        tokenRepository.save(token);

        user.changePasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        auditLogService.record(AuditEventType.PASSWORD_RESET_COMPLETED, user.getEmail(), user.getId(), metadata);
        sessionService.revokeAllSessions(user.getId(), metadata);
    }
}
