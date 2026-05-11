package io.github.deshenrao.auth0lite.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class TokenBucketTest {

    @Test
    void allowsConsumptionUpToCapacityThenRejects() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        TokenBucket bucket = new TokenBucket(3, Duration.ofMinutes(1), now);

        assertThat(bucket.tryConsume(now)).isTrue();
        assertThat(bucket.tryConsume(now)).isTrue();
        assertThat(bucket.tryConsume(now)).isTrue();
        assertThat(bucket.tryConsume(now)).isFalse();
    }

    @Test
    void refillsTokensGraduallyOverTime() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        TokenBucket bucket = new TokenBucket(2, Duration.ofMinutes(1), now);

        assertThat(bucket.tryConsume(now)).isTrue();
        assertThat(bucket.tryConsume(now)).isTrue();
        assertThat(bucket.tryConsume(now)).isFalse();

        Instant halfMinuteLater = now.plus(Duration.ofSeconds(31));
        assertThat(bucket.tryConsume(halfMinuteLater)).isTrue();
        assertThat(bucket.tryConsume(halfMinuteLater)).isFalse();
    }

    @Test
    void secondsUntilNextTokenIsZeroWhenTokensAreAvailable() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        TokenBucket bucket = new TokenBucket(1, Duration.ofMinutes(1), now);

        assertThat(bucket.secondsUntilNextToken(now)).isZero();
    }

    @Test
    void secondsUntilNextTokenIsPositiveOnceExhausted() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        TokenBucket bucket = new TokenBucket(1, Duration.ofMinutes(1), now);
        bucket.tryConsume(now);

        assertThat(bucket.secondsUntilNextToken(now)).isGreaterThan(0);
    }

    @Test
    void neverExceedsCapacityEvenAfterALongIdlePeriod() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        TokenBucket bucket = new TokenBucket(2, Duration.ofMinutes(1), now);

        Instant muchLater = now.plus(Duration.ofDays(1));
        assertThat(bucket.tryConsume(muchLater)).isTrue();
        assertThat(bucket.tryConsume(muchLater)).isTrue();
        assertThat(bucket.tryConsume(muchLater)).isFalse();
    }
}
