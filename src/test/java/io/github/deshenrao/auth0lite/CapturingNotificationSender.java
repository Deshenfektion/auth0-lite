package io.github.deshenrao.auth0lite;

import io.github.deshenrao.auth0lite.notification.NotificationSender;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class CapturingNotificationSender implements NotificationSender {

    private final Map<String, String> lastVerificationTokenByEmail = new ConcurrentHashMap<>();
    private final Map<String, String> lastPasswordResetTokenByEmail = new ConcurrentHashMap<>();

    @Override
    public void sendEmailVerification(String toEmail, String rawToken) {
        lastVerificationTokenByEmail.put(toEmail, rawToken);
    }

    @Override
    public void sendPasswordReset(String toEmail, String rawToken) {
        lastPasswordResetTokenByEmail.put(toEmail, rawToken);
    }

    public String lastVerificationTokenFor(String email) {
        return lastVerificationTokenByEmail.get(email);
    }

    public String lastPasswordResetTokenFor(String email) {
        return lastPasswordResetTokenByEmail.get(email);
    }
}
