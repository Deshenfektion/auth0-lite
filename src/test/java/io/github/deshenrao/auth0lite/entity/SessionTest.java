package io.github.deshenrao.auth0lite.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class SessionTest {

    @Test
    void isActiveWhenNeitherRevokedNorExpired() {
        Instant now = Instant.now();
        Session session = new Session(UUID.randomUUID(), UUID.randomUUID(), now,
                now.plusSeconds(3600), "127.0.0.1", "junit");

        assertThat(session.isActive(now)).isTrue();
    }

    @Test
    void isNotActiveOnceExpired() {
        Instant now = Instant.now();
        Session session = new Session(UUID.randomUUID(), UUID.randomUUID(), now,
                now.plusSeconds(60), "127.0.0.1", "junit");

        assertThat(session.isActive(now.plusSeconds(61))).isFalse();
    }

    @Test
    void isNotActiveOnceRevoked() {
        Instant now = Instant.now();
        Session session = new Session(UUID.randomUUID(), UUID.randomUUID(), now,
                now.plusSeconds(3600), "127.0.0.1", "junit");

        session.revoke(now);

        assertThat(session.isActive(now)).isFalse();
    }

    @Test
    void recordActivityUpdatesLastActivityIpAndUserAgent() {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        Session session = new Session(UUID.randomUUID(), UUID.randomUUID(), createdAt,
                createdAt.plusSeconds(3600), "127.0.0.1", "original-agent");

        Instant activityAt = createdAt.plusSeconds(30);
        session.recordActivity(activityAt, "203.0.113.5", "new-agent");

        assertThat(session.getLastActivityAt()).isEqualTo(activityAt);
        assertThat(session.getIpAddress()).isEqualTo("203.0.113.5");
        assertThat(session.getUserAgent()).isEqualTo("new-agent");
    }
}
