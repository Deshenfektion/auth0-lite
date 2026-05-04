package io.github.deshenrao.auth0lite.repository;

import io.github.deshenrao.auth0lite.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {

    List<Session> findByUserIdAndRevokedAtIsNull(UUID userId);

    @Modifying
    @Query("update Session s set s.revokedAt = :revokedAt where s.userId = :userId and s.revokedAt is null")
    void revokeAllForUser(@Param("userId") UUID userId, @Param("revokedAt") Instant revokedAt);
}
