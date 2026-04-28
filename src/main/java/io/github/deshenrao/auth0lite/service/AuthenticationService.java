package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.domain.AuditEventType;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.AccountLockedException;
import io.github.deshenrao.auth0lite.exception.InvalidCredentialsException;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AccountLockoutService accountLockoutService;
    private final AuditLogService auditLogService;
    private final String dummyPasswordHash;

    public AuthenticationService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AccountLockoutService accountLockoutService,
            AuditLogService auditLogService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.accountLockoutService = accountLockoutService;
        this.auditLogService = auditLogService;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public User login(LoginRequest request, RequestMetadata metadata) {
        String normalizedEmail = request.email().strip().toLowerCase();
        Optional<User> maybeUser = userRepository.findByEmailWithRoles(normalizedEmail);

        if (maybeUser.isPresent() && maybeUser.get().isCurrentlyLocked(Instant.now())) {
            User lockedUser = maybeUser.get();
            auditLogService.record(
                    AuditEventType.LOGIN_BLOCKED_ACCOUNT_LOCKED, normalizedEmail, lockedUser.getId(), metadata);
            throw new AccountLockedException(lockedUser.getLockedUntil());
        }

        String hashToVerify = maybeUser.map(User::getPasswordHash).orElse(dummyPasswordHash);
        boolean passwordMatches = passwordEncoder.matches(request.password(), hashToVerify);

        if (maybeUser.isEmpty() || !passwordMatches) {
            maybeUser.ifPresent(user -> accountLockoutService.recordFailedAttempt(user.getId()));
            auditLogService.record(
                    AuditEventType.LOGIN_FAILURE,
                    normalizedEmail,
                    maybeUser.map(User::getId).orElse(null),
                    metadata
            );
            throw new InvalidCredentialsException();
        }

        User user = maybeUser.get();

        if (!user.isEnabled()) {
            auditLogService.record(
                    AuditEventType.LOGIN_BLOCKED_ACCOUNT_DISABLED, normalizedEmail, user.getId(), metadata);
            throw new InvalidCredentialsException();
        }

        accountLockoutService.recordSuccessfulLogin(user.getId());
        auditLogService.record(AuditEventType.LOGIN_SUCCESS, normalizedEmail, user.getId(), metadata);
        return user;
    }
}
