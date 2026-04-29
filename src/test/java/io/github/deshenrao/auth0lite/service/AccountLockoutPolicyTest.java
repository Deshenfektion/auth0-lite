package io.github.deshenrao.auth0lite.service;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class AccountLockoutPolicyTest {

    private final AccountLockoutPolicy policy = new AccountLockoutPolicy();

    @Test
    void returnsNoLockBelowFirstThreshold() {
        assertThat(policy.lockDurationFor(4)).isEmpty();
    }

    @Test
    void locksForOneMinuteAtFirstThreshold() {
        assertThat(policy.lockDurationFor(5)).contains(Duration.ofMinutes(1));
    }

    @Test
    void locksForFiveMinutesAtSecondThreshold() {
        assertThat(policy.lockDurationFor(10)).contains(Duration.ofMinutes(5));
    }

    @Test
    void capsLockDurationAtFifteenMinutes() {
        assertThat(policy.lockDurationFor(15)).contains(Duration.ofMinutes(15));
        assertThat(policy.lockDurationFor(1000)).contains(Duration.ofMinutes(15));
    }
}
