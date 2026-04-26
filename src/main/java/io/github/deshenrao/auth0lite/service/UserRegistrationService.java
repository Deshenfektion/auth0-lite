package io.github.deshenrao.auth0lite.service;

import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.entity.Role;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.exception.EmailAlreadyRegisteredException;
import io.github.deshenrao.auth0lite.repository.RoleRepository;
import io.github.deshenrao.auth0lite.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserRegistrationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User register(RegisterUserRequest request) {
        String normalizedEmail = request.email().strip().toLowerCase();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyRegisteredException(normalizedEmail);
        }

        String passwordHash = passwordEncoder.encode(request.password());
        User user = new User(normalizedEmail, passwordHash);
        user.assignRole(defaultRole());

        try {
            return userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            throw new EmailAlreadyRegisteredException(normalizedEmail);
        }
    }

    private Role defaultRole() {
        return roleRepository.findByName(RoleName.USER)
                .orElseThrow(() -> new IllegalStateException("Default role USER is not seeded"));
    }
}
