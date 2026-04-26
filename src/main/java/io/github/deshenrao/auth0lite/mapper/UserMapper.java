package io.github.deshenrao.auth0lite.mapper;

import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.Role;
import io.github.deshenrao.auth0lite.entity.User;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class UserMapper {

    public UserResponse toResponse(User user) {
        Set<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .map(RoleName::name)
                .collect(Collectors.toSet());

        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.isEmailVerified(),
                user.isEnabled(),
                roleNames,
                user.getCreatedAt()
        );
    }
}
