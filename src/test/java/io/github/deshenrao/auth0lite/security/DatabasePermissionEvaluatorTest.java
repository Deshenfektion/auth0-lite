package io.github.deshenrao.auth0lite.security;

import io.github.deshenrao.auth0lite.domain.JwtPrincipal;
import io.github.deshenrao.auth0lite.repository.PermissionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DatabasePermissionEvaluatorTest {

    @Mock
    private PermissionRepository permissionRepository;

    @Test
    void grantsAccessWhenUserHasThePermission() {
        DatabasePermissionEvaluator evaluator = new DatabasePermissionEvaluator(permissionRepository);
        UUID userId = UUID.randomUUID();
        JwtPrincipal principal = new JwtPrincipal(userId, UUID.randomUUID(), "admin@example.com");
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());

        when(permissionRepository.findPermissionNamesForUser(userId))
                .thenReturn(Set.of("sessions:revoke:any"));

        assertThat(evaluator.hasPermission(authentication, null, "sessions:revoke:any")).isTrue();
    }

    @Test
    void deniesAccessWhenUserLacksThePermission() {
        DatabasePermissionEvaluator evaluator = new DatabasePermissionEvaluator(permissionRepository);
        UUID userId = UUID.randomUUID();
        JwtPrincipal principal = new JwtPrincipal(userId, UUID.randomUUID(), "user@example.com");
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());

        when(permissionRepository.findPermissionNamesForUser(userId)).thenReturn(Set.of());

        assertThat(evaluator.hasPermission(authentication, null, "sessions:revoke:any")).isFalse();
    }

    @Test
    void deniesAccessWhenPrincipalIsNotAJwtPrincipal() {
        DatabasePermissionEvaluator evaluator = new DatabasePermissionEvaluator(permissionRepository);
        Authentication authentication = new UsernamePasswordAuthenticationToken("not-a-jwt-principal", null, List.of());

        assertThat(evaluator.hasPermission(authentication, null, "sessions:revoke:any")).isFalse();
    }
}
