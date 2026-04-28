package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class AccountLockoutService {

    private final UserRepository userRepository;
    private final AccountLockoutPolicy lockoutPolicy;

    public AccountLockoutService(UserRepository userRepository, AccountLockoutPolicy lockoutPolicy) {
        this.userRepository = userRepository;
        this.lockoutPolicy = lockoutPolicy;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailedAttempt(UUID userId) {
        userRepository.findById(userId).ifPresent(user -> {
            int attempts = user.registerFailedAttempt(Instant.now());
            lockoutPolicy.lockDurationFor(attempts)
                    .ifPresent(duration -> user.lockUntil(Instant.now().plus(duration)));
            userRepository.save(user);
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccessfulLogin(UUID userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.resetFailedAttempts();
            userRepository.save(user);
        });
    }
}
