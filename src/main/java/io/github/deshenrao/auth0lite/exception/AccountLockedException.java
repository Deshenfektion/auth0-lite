package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

import java.time.Instant;

public class AccountLockedException extends ApiException {

    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super(HttpStatus.LOCKED, "Account is temporarily locked due to repeated failed login attempts. "
                + "Try again later.");
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
