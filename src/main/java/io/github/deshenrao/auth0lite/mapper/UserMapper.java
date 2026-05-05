package io.github.deshenrao.auth0lite.mapper;

import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.domain.TokenSubject;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.Role;
import io.github.deshenrao.auth0lite.entity.User;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class UserMapper {

    public UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.isEmailVerified(),
                user.isEnabled(),
                roleNames(user).collect(Collectors.toSet()),
                user.getCreatedAt()
        );
    }

    public TokenSubject toTokenSubject(User user, UUID sessionId) {
        return new TokenSubject(user.getId(), sessionId, user.getEmail(), roleNames(user).toList());
    }

    private Stream<String> roleNames(User user) {
        return user.getRoles().stream()
                .map(Role::getName)
                .map(RoleName::name);
    }
}
