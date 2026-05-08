package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.EmailVerificationProperties;
import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.GeneratedToken;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.EmailVerificationToken;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidVerificationTokenException;
import io.github.deshenrao.auth0lite.notification.NotificationSender;
import io.github.deshenrao.auth0lite.repository.EmailVerificationTokenRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import io.github.deshenrao.auth0lite.security.SecureTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class EmailVerificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final SecureTokenGenerator tokenGenerator;
    private final NotificationSender notificationSender;
    private final AuditLogService auditLogService;
    private final EmailVerificationProperties properties;
    private final Clock clock;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokenRepository,
            UserRepository userRepository,
            SecureTokenGenerator tokenGenerator,
            NotificationSender notificationSender,
            AuditLogService auditLogService,
            EmailVerificationProperties properties,
            Clock clock
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.tokenGenerator = tokenGenerator;
        this.notificationSender = notificationSender;
        this.auditLogService = auditLogService;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public void sendVerificationEmail(UUID userId, String email) {
        GeneratedToken token = tokenGenerator.generate();
        Instant now = clock.instant();
        EmailVerificationToken entity = new EmailVerificationToken(
                userId, token.hash(), now, now.plus(properties.ttl()));
        tokenRepository.save(entity);

        try {
            notificationSender.sendEmailVerification(email, token.rawValue());
        } catch (RuntimeException exception) {
            log.error("Failed to send verification email to {}", email, exception);
        }
    }

    @Transactional
    public void resendVerificationEmail(String email) {
        String normalizedEmail = email.strip().toLowerCase();
        userRepository.findByEmail(normalizedEmail)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(user -> sendVerificationEmail(user.getId(), user.getEmail()));
    }

    @Transactional
    public void verifyEmail(String rawToken, RequestMetadata metadata) {
        EmailVerificationToken token = tokenRepository.findByTokenHash(tokenGenerator.hash(rawToken))
                .orElseThrow(InvalidVerificationTokenException::new);

        Instant now = clock.instant();
        if (token.isUsed() || token.isExpired(now)) {
            throw new InvalidVerificationTokenException();
        }

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(InvalidVerificationTokenException::new);

        token.markUsed(now);
        tokenRepository.save(token);

        user.markEmailVerified();
        userRepository.save(user);

        auditLogService.record(AuditEventType.EMAIL_VERIFIED, user.getEmail(), user.getId(), metadata);
    }
}
