package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.domain.JwtPrincipal;
import io.github.deshenrao.auth0lite.repository.PermissionRepository;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class DatabasePermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository;

    public DatabasePermissionEvaluator(PermissionRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (!(authentication.getPrincipal() instanceof JwtPrincipal principal)) {
            return false;
        }

        return permissionRepository.findPermissionNamesForUser(principal.userId())
                .contains(permission.toString());
    }

    @Override
    public boolean hasPermission(
            Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
