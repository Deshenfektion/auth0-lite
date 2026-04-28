package io.github.deshenrao.auth0lite.service;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
public class AccountLockoutPolicy {

    private static final int[] ATTEMPT_THRESHOLDS = {5, 10, 15};
    private static final Duration[] LOCK_DURATIONS = {
            Duration.ofMinutes(1),
            Duration.ofMinutes(5),
            Duration.ofMinutes(15)
    };

    public Optional<Duration> lockDurationFor(int failedAttempts) {
        Duration duration = null;
        for (int i = 0; i < ATTEMPT_THRESHOLDS.length; i++) {
            if (failedAttempts >= ATTEMPT_THRESHOLDS[i]) {
                duration = LOCK_DURATIONS[i];
            }
        }
        return Optional.ofNullable(duration);
    }
}
