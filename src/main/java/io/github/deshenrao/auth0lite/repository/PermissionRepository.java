package io.github.deshenrao.auth0lite.repository;

import io.github.deshenrao.auth0lite.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Set;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    @Query(value = """
            select distinct p.name
            from permissions p
            join role_permissions rp on rp.permission_id = p.id
            join user_roles ur on ur.role_id = rp.role_id
            where ur.user_id = :userId
            """, nativeQuery = true)
    Set<String> findPermissionNamesForUser(@Param("userId") UUID userId);
}
