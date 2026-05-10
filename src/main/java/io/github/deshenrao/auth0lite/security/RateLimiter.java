package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.config.RateLimitProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimiter {

    private final RateLimitProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(RateLimitProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public boolean tryConsume(String key) {
        return bucketFor(key).tryConsume(clock.instant());
    }

    public long secondsUntilNextToken(String key) {
        return bucketFor(key).secondsUntilNextToken(clock.instant());
    }

    private TokenBucket bucketFor(String key) {
        return buckets.computeIfAbsent(
                key, ignored -> new TokenBucket(properties.capacity(), properties.refillPeriod(), clock.instant()));
    }
}
