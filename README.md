# Auth0-Lite

A miniature Auth0/Okta-style identity provider, built from scratch to demonstrate production-grade backend engineering — no black-box auth library standing in for the parts worth understanding.

## Stack

Java 21 · Spring Boot 3.5 · Spring Security · PostgreSQL · Flyway · Gradle (Kotlin DSL) · Docker · Testcontainers · springdoc-openapi

## Features

- Registration & login — Argon2id hashing, timing-safe verification, progressive account lockout, audit trail

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Swagger UI: http://localhost:8080/swagger-ui.html

## Testing

```bash
./gradlew test
```

Integration tests spin up Postgres via Testcontainers automatically — no manual setup.
