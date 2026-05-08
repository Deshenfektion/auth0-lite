package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.InvalidCurrentPasswordException;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class ChangePasswordService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final AuditLogService auditLogService;

    public ChangePasswordService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            SessionService sessionService,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public void changePassword(
            UUID userId,
            UUID currentSessionId,
            String currentPassword,
            String newPassword,
            RequestMetadata metadata
    ) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("Authenticated user no longer exists"));

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new InvalidCurrentPasswordException();
        }

        user.changePasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        auditLogService.record(AuditEventType.PASSWORD_CHANGED, user.getEmail(), user.getId(), metadata);
        sessionService.revokeAllSessionsExcept(userId, currentSessionId, metadata);
    }
}
