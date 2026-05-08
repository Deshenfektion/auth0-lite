package io.github.deshenrao.auth0lite.notification;

public interface NotificationSender {

    void sendEmailVerification(String toEmail, String rawToken);

    void sendPasswordReset(String toEmail, String rawToken);
}
