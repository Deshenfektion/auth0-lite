package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.config.EmailVerificationProperties;
import io.github.deshenrao.auth0lite.notification.NotificationSender;
import io.github.deshenrao.auth0lite.repository.EmailVerificationTokenRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import io.github.deshenrao.auth0lite.security.SecureTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceTest {

    @Mock
    private EmailVerificationTokenRepository tokenRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private NotificationSender notificationSender;

    @Mock
    private AuditLogService auditLogService;

    private final SecureTokenGenerator tokenGenerator = new SecureTokenGenerator();
    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final EmailVerificationProperties properties = new EmailVerificationProperties(Duration.ofDays(1));

    private EmailVerificationService service;

    @BeforeEach
    void setUp() {
        service = new EmailVerificationService(
                tokenRepository, userRepository, tokenGenerator, notificationSender, auditLogService, properties,
                clock);
    }

    @Test
    void sendVerificationEmailDoesNotPropagateANotificationProviderFailure() {
        doThrow(new RuntimeException("provider outage")).when(notificationSender)
                .sendEmailVerification(any(), any());

        assertThatCode(() -> service.sendVerificationEmail(UUID.randomUUID(), "user@example.com"))
                .doesNotThrowAnyException();

        verify(tokenRepository).save(any());
    }
}
