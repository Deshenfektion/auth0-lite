package io.github.deshenrao.auth0lite.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class UserLockoutTest {

    @Test
    void isCurrentlyLockedReturnsTrueWhileLockIsInEffect() {
        User user = new User("test@example.com", "irrelevant-hash");
        Instant now = Instant.now();
        user.lockUntil(now.plusSeconds(60));

        assertThat(user.isCurrentlyLocked(now)).isTrue();
    }

    @Test
    void isCurrentlyLockedReturnsFalseOnceLockHasExpired() {
        User user = new User("test@example.com", "irrelevant-hash");
        Instant now = Instant.now();
        user.lockUntil(now.plusSeconds(60));

        assertThat(user.isCurrentlyLocked(now.plusSeconds(61))).isFalse();
    }

    @Test
    void registerFailedAttemptClearsStaleExpiredLockBeforeIncrementing() {
        User user = new User("test@example.com", "irrelevant-hash");
        Instant now = Instant.now();

        for (int i = 0; i < 5; i++) {
            user.registerFailedAttempt(now);
        }
        user.lockUntil(now.plusSeconds(1));

        int attemptsAfterExpiry = user.registerFailedAttempt(now.plusSeconds(2));

        assertThat(attemptsAfterExpiry).isEqualTo(1);
        assertThat(user.isCurrentlyLocked(now.plusSeconds(2))).isFalse();
    }

    @Test
    void resetFailedAttemptsClearsCounterAndLock() {
        User user = new User("test@example.com", "irrelevant-hash");
        Instant now = Instant.now();
        user.registerFailedAttempt(now);
        user.lockUntil(now.plusSeconds(60));

        user.resetFailedAttempts();

        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
    }
}
