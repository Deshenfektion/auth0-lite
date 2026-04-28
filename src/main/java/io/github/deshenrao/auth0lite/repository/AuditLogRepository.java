package io.github.deshenrao.auth0lite.repository;

import io.github.deshenrao.auth0lite.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
}
