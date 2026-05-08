package io.github.deshenrao.auth0lite.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoggingNotificationSender implements NotificationSender {

    private static final Logger log = LoggerFactory.getLogger(LoggingNotificationSender.class);

    @Override
    public void sendEmailVerification(String toEmail, String rawToken) {
        log.info("[MOCK EMAIL] Verification link for {} -> token={}", toEmail, rawToken);
    }

    @Override
    public void sendPasswordReset(String toEmail, String rawToken) {
        log.info("[MOCK EMAIL] Password reset link for {} -> token={}", toEmail, rawToken);
    }
}
