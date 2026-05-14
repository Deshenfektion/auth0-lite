# Auth0-Lite

A miniature Auth0/Okta-style identity provider, built from scratch to demonstrate production-grade backend engineering — no black-box auth library standing in for the parts worth understanding.

## Stack

Java 21 · Spring Boot 3.5 · Spring Security · PostgreSQL · Flyway · Nimbus JOSE+JWT · Gradle (Kotlin DSL) · Docker · Testcontainers · springdoc-openapi

## Features

- Registration & login — Argon2id hashing, timing-safe verification, progressive account lockout, audit trail
- JWT access tokens signed with RS256, published via a JWKS endpoint
- Rotating refresh tokens with reuse/theft detection
- Device-aware session management (list, revoke, logout everywhere)
- Role- and permission-based authorization via `@RequiresRole` / `@RequiresPermission`
- Email verification, password reset & change
- Rate limiting, CORS, security headers

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Swagger UI: http://localhost:8080/swagger-ui.html

Or run against a local Gradle build:

```bash
./gradlew bootRun --args='--spring.profiles.active=dev'
```

`dev`/`test` generate an ephemeral RSA signing key on every startup. `prod` requires one to persist across restarts:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key.pem
export JWT_PRIVATE_KEY_PEM="$(cat private-key.pem)"
```

## Testing

```bash
./gradlew test
```

Integration tests spin up Postgres via Testcontainers automatically — no manual setup. On Colima,
set `docker.host` in `~/.testcontainers.properties`; if Ryuk fails to start, run with
`TESTCONTAINERS_RYUK_DISABLED=true`.

## Design notes

- Flyway owns the schema; `ddl-auto=validate` everywhere, so Hibernate never mutates it silently.
- Errors are uniform RFC 7807 `ProblemDetail` responses.
- Stateless security throughout — no HTTP sessions, no CSRF surface, bearer tokens only.
- HS256 access tokens were replaced with RS256 + JWKS once more than one service needed to verify them.
- Rate limiting is an in-memory token bucket; needs a shared store (Redis) beyond a single instance.

## Out of scope

No social login, no multi-tenancy, no real email delivery (mock sender behind a `NotificationSender`
seam), no GDPR export/delete, single active JWKS key with no rotation trigger.
