package io.github.deshenrao.auth0lite.security;

import java.time.Duration;
import java.time.Instant;

public class TokenBucket {

    private final int capacity;
    private final double refillTokensPerMillisecond;
    private double availableTokens;
    private Instant lastRefill;

    public TokenBucket(int capacity, Duration refillPeriod, Instant now) {
        this.capacity = capacity;
        this.refillTokensPerMillisecond = (double) capacity / refillPeriod.toMillis();
        this.availableTokens = capacity;
        this.lastRefill = now;
    }

    public synchronized boolean tryConsume(Instant now) {
        refill(now);
        if (availableTokens >= 1.0) {
            availableTokens -= 1.0;
            return true;
        }
        return false;
    }

    public synchronized long secondsUntilNextToken(Instant now) {
        refill(now);
        if (availableTokens >= 1.0) {
            return 0;
        }
        double tokensNeeded = 1.0 - availableTokens;
        double millisNeeded = tokensNeeded / refillTokensPerMillisecond;
        return (long) Math.ceil(millisNeeded / 1000.0);
    }

    private void refill(Instant now) {
        long elapsedMillis = Duration.between(lastRefill, now).toMillis();
        if (elapsedMillis > 0) {
            availableTokens = Math.min(capacity, availableTokens + elapsedMillis * refillTokensPerMillisecond);
            lastRefill = now;
        }
    }
}
