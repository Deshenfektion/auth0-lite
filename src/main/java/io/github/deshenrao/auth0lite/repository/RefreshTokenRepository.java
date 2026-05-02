package io.github.deshenrao.auth0lite.repository;

import io.github.deshenrao.auth0lite.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying
    @Query("update RefreshToken r set r.revokedAt = :revokedAt where r.familyId = :familyId and r.revokedAt is null")
    void revokeFamily(@Param("familyId") UUID familyId, @Param("revokedAt") Instant revokedAt);
}
