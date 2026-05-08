package io.github.deshenrao.auth0lite.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken extends SingleUseToken {

    protected PasswordResetToken() {
    }

    public PasswordResetToken(UUID userId, String tokenHash, Instant createdAt, Instant expiresAt) {
        super(userId, tokenHash, createdAt, expiresAt);
    }
}
