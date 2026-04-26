package io.github.deshenrao.auth0lite.repository;

import io.github.deshenrao.auth0lite.domain.RoleName;
import io.github.deshenrao.auth0lite.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(RoleName name);
}
