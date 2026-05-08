package io.github.deshenrao.auth0lite.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "email_verification_tokens")
public class EmailVerificationToken extends SingleUseToken {

    protected EmailVerificationToken() {
    }

    public EmailVerificationToken(UUID userId, String tokenHash, Instant createdAt, Instant expiresAt) {
        super(userId, tokenHash, createdAt, expiresAt);
    }
}
