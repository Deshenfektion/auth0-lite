package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.config.RateLimitProperties;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void differentKeysHaveIndependentBuckets() {
        RateLimiter rateLimiter = new RateLimiter(new RateLimitProperties(1, Duration.ofMinutes(1)), clock);

        assertThat(rateLimiter.tryConsume("key-a")).isTrue();
        assertThat(rateLimiter.tryConsume("key-a")).isFalse();
        assertThat(rateLimiter.tryConsume("key-b")).isTrue();
    }

    @Test
    void sameKeyIsRateLimitedAcrossCalls() {
        RateLimiter rateLimiter = new RateLimiter(new RateLimitProperties(2, Duration.ofMinutes(1)), clock);

        assertThat(rateLimiter.tryConsume("shared-key")).isTrue();
        assertThat(rateLimiter.tryConsume("shared-key")).isTrue();
        assertThat(rateLimiter.tryConsume("shared-key")).isFalse();
        assertThat(rateLimiter.secondsUntilNextToken("shared-key")).isGreaterThan(0);
    }
}
