package io.github.deshenrao.auth0lite.entity;

import io.github.deshenrao.auth0lite.domain.RoleName;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true, length = 50)
    private RoleName name;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected Role() {
    }

    public UUID getId() {
        return id;
    }

    public RoleName getName() {
        return name;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
