# axum-gate

[![Crates.io](https://img.shields.io/crates/v/axum-gate.svg)](https://crates.io/crates/axum-gate)
[![Documentation](https://docs.rs/axum-gate/badge.svg)](https://docs.rs/axum-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/axum-gate/workflows/CI/badge.svg)](https://github.com/emirror-de/axum-gate/actions)

Flexible, type-safe authentication and authorization for Axum using JWTs.
- Cookie and bearer authentication
- Hierarchical roles, groups, and string-based permissions
- Ready-to-use login/logout handlers
- In-memory and optional database-backed repositories

## Install

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
axum-gate = { version = "1.0.0-rc.0" }
```

Optional features:
- storage-surrealdb — SurrealDB repositories
- storage-seaorm — SeaORM repositories
- audit-logging — structured audit events
- prometheus — metrics for audit (implies audit-logging)
- insecure-fast-hash — faster Argon2 preset for development only

## Core concepts

- Gate layer
  - Gate::cookie("issuer", codec): JWT via HTTP-only cookies (web apps)
  - Gate::bearer("issuer", codec): JWT via Authorization: Bearer header (APIs)
  - allow_anonymous_with_optional_user(): never block; inserts optional user context
  - require_login(): allow baseline role and all supervisors (hierarchy)
- Access policies
  - require_role(..), require_role_or_supervisor(..)
  - require_group(..)
  - require_permission("domain:action") — deterministic hashing to PermissionId
- Login/logout
  - route_handlers::login: verifies credentials and sets the auth cookie
  - route_handlers::logout: removes the auth cookie
- Repositories
  - repositories::memory::{MemoryAccountRepository, MemorySecretRepository}
  - Optional SurrealDB / SeaORM backends via feature flags
- JWT codec
  - codecs::jwt::JsonWebToken with JsonWebTokenOptions (use persistent keys in production)

## Security

- Use a persistent JWT key (do not rely on the default random key in production)
- Keep the issuer consistent between Gate configuration and RegisteredClaims
- Use secure cookie settings in production (HttpOnly, Secure, appropriate SameSite)
- Rate-limit sensitive endpoints (e.g., login)

## Examples and docs

Examples and complete usage are available in the crate documentation on docs.rs:
https://docs.rs/axum-gate

## MSRV and license

- MSRV: 1.86
- License: MIT
