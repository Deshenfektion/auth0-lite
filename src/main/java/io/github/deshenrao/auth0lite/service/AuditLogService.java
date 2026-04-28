package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.AuditLog;
import io.github.deshenrao.auth0lite.repository.AuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType eventType, String email, UUID userId, RequestMetadata metadata) {
        AuditLog auditLog = new AuditLog(eventType, email, userId, metadata.ipAddress(), metadata.userAgent());
        auditLogRepository.save(auditLog);
    }
}
