# axum-gate

[![Crates.io](https://img.shields.io/crates/v/axum-gate.svg)](https://crates.io/crates/axum-gate)
[![Documentation](https://docs.rs/axum-gate/badge.svg)](https://docs.rs/axum-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/axum-gate/workflows/CI/badge.svg)](https://github.com/emirror-de/axum-gate/actions)

**Version:** `v1.0.0`

**axum-gate** is a flexible, type-safe authentication & authorization library for [axum]. It provides production-ready JWT cookie authentication, hierarchical role & permission management, and a clean architecture that scales from simple single-node services to distributed deployments.

## Status

`v1.0.0` is the first stable release. The public API follows [Semantic Versioning](https://semver.org/).

Report issues or ergonomic improvement ideas via GitHub Issues or Discussions.

## Highlights

- Secure JWT (HMAC) cookie authentication with configurable lifetimes
- Hierarchical role model with supervisor / subordinate semantics
- Dense, roaring-bitmap powered permission sets (fast membership tests)
- Test-time permission collision validation & enumeration helpers
- Pluggable account + secret storage (can be fully separated)
- Multiple storage backends: in-memory (default), SurrealDB, SeaORM
- Deterministic hashing / zero cross-node sync for permission evaluation
- Explicit boundary between domain, application services, and infrastructure
- Strong error typing, easily convertible to axum responses
- Example-driven documentation: basic usage, distributed setup, rate limiting, SurrealDB, SeaORM, custom roles, permission validation
- Works with tower middleware layering & standard axum patterns
- Production-ready observability planned: Prometheus metrics, audit trails, structured logging (v1.1.0)

## Feature Flags

| Feature | Description |
| ------- | ----------- |
| `storage-surrealdb` | Enables SurrealDB repository implementation |
| `storage-seaorm` | Enables SeaORM repository implementation |
| `insecure-fast-hash` | Opt-in (release) / automatic in debug: a reduced Argon2 preset for faster local iteration. Never enable in production. |
| `metrics-prometheus` | Enables Prometheus metrics integration (planned v1.1.0) |
| `observability-full` | Enables comprehensive observability features including audit trails (planned v1.1.0) |

## Installation

In your `Cargo.toml`:

```toml
[dependencies]
axum-gate = { version = "1.0.0", features = ["storage-surrealdb"] } # choose the backends you need
```

For SeaORM support:

```toml
axum-gate = { version = "1.0.0", features = ["storage-seaorm"] }
```

For purely in-memory (tests / prototypes):

```toml
axum-gate = "1.0.0"
```

## Quick Start

Define your roles & permissions (or use simple numeric roles if you prefer). A typical pattern uses `strum` derive enums:

```rust
use axum_gate::prelude::*;
use strum::{EnumIter, IntoEnumIterator};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum AppPermission {
    ViewDashboard,
    ManageUsers,
    BillingRead,
    BillingWrite,
}

impl PermissionSet for AppPermission {
    fn iter() -> Box<dyn Iterator<Item = Self>> {
        Box::new(Self::iter())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppRole {
    User,
    Admin,
}

impl RoleDefinition for AppRole {
    type Permission = AppPermission;

    fn permissions(self) -> PermissionMask<Self::Permission> {
        match self {
            Self::User => mask![AppPermission::ViewDashboard],
            Self::Admin => mask![
                AppPermission::ViewDashboard,
                AppPermission::ManageUsers,
                AppPermission::BillingRead,
                AppPermission::BillingWrite
            ],
        }
    }

    fn parents(self) -> &'static [Self] {
        match self {
            Self::User => &[],
            Self::Admin => &[Self::User],
        }
    }
}
```

Build authentication / authorization services and layer them into axum:

```rust
use axum::{routing::get, Router};
use axum_gate::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // In-memory repositories (swap for SeaORM / SurrealDB in production)
    let account_repo = Arc::new(InMemoryAccountRepository::default());
    let secret_repo = Arc::new(InMemorySecretRepository::default());

    // Services
    let login_svc = LoginService::new(account_repo.clone(), secret_repo.clone());
    let authz_svc = AuthorizationService::<AppRole>::new();

    // JWT manager (choose secure, long, random key; keep out of source control)
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let jwt = JwtManager::new(jwt_secret.as_bytes());

    // Gate layer (extracts session + permissions)
    let gate_layer = GateLayer::new(jwt.clone(), authz_svc);

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/dashboard", get(dashboard_handler))
        .layer(gate_layer); // apply after defining protected routes

    // Provide login/logout handlers (simplified example)
    // See examples for full flows incl. password hash creation.

    println!("Listening on 0.0.0.0:3000");
    axum::serve(
        tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(),
        app,
    )
    .await
    .unwrap();
}

async fn dashboard_handler(AuthenticatedAccount(account): AuthenticatedAccount<AppRole>) -> String {
    format!("Welcome, account {}", account.id)
}
```

See the `/examples` directory for fully working code (distributed deployment, rate limiting integration, SeaORM models, SurrealDB schema, custom permission validation).

## Architecture

The library is structured along clean architecture principles:

- Web (axum): extractors, layers, response mappers
- Application services: login, account provisioning, permission evaluation
- Domain: role graph, permission bitsets, session claims
- Infrastructure: repositories (in-memory, SurrealDB, SeaORM), password hashing, JWT signing

This separation promotes testability & substitution of components without touching core logic.

## Security Notes

- Uses Argon2 for password hashing (strong preset in release builds)
- Optional fast-hash preset for local dev only (`insecure-fast-hash`)
- **JWT Secret Management**
  - Never hardcode secrets in source code
  - Use high-entropy secrets (≥32 bytes)
  - Load from environment variables or secret management systems
  - Different secrets for dev/staging/production environments
- JWT cookies should be:
  - `HttpOnly`
  - `Secure` (always when using TLS)
  - `SameSite=Strict` or `Lax` depending on application needs
- Implement rate limiting (see `examples/rate-limiting`) on login endpoints
- Store the signing secret outside source control (env var / secret manager)
- Rotate secrets carefully; plan for multi-key verification if you need seamless rotation in future versions

### Security Audit Status

**Note**: The following RUSTSEC advisories are temporarily disabled in our audit process:
- `RUSTSEC-2023-0071`: Temporarily ignored while evaluating impact and mitigation strategies
- `RUSTSEC-2024-0436`: Temporarily ignored pending dependency updates

These advisories are being actively monitored and will be addressed in upcoming releases. The decision to temporarily disable them allows for continued development while proper fixes are implemented.

## Error Handling

Errors implement rich variants enabling mapping to structured HTTP responses. When integrating, convert them to your API error format or reuse provided helpers.

## Examples Overview

| Example | Focus |
| ------- | ----- |
| `basic` | Minimal setup & login flow |
| `simple-usage` | Streamlined API usage with default services |
| `distributed` | Deterministic permission hashing across nodes |
| `permission-validation` | Test-time + runtime permission checks |
| `rate-limiting` | Integration with tower rate limiting middleware |
| `surrealdb` | SurrealDB storage backend |
| `sea-orm` | SeaORM backend integration |
| `custom-roles` | Advanced role / permission definitions |

Run one:

```bash
cargo run --example basic
```

With a feature:

```bash
cargo run --example surrealdb --features storage-surrealdb
```

## Versioning & Stability

### Semantic Versioning
- **Patch (1.0.x)**: bug fixes & internal improvements (no API changes)
- **Minor (1.x.0)**: backward-compatible additions & performance work
- **Major (x.0.0)**: breaking changes (accompanied by migration notes)

### Minimum Supported Rust Version (MSRV)
**Current MSRV**: Rust 1.85.0

**MSRV Policy**:
- MSRV will only be raised in **minor** or **major** releases, never in patch releases
- MSRV increases require clear justification (new language features, dependency requirements, security improvements)
- When MSRV is raised, the changelog will document the reasons and new minimum version
- We aim to support at least the last 6 months of Rust releases when practical
- MSRV is tested in CI to prevent accidental breakage

**Compatibility Promise**:
- Public APIs are considered stable within major versions
- Internal modules (`crate::domain`, `crate::infrastructure`, etc.) may change in minor releases
- Breaking changes will be clearly documented with migration guides

### Security
Coordinated disclosure details available in [SECURITY.md](SECURITY.md)

## Contributing

Contributions are welcome—tests & documentation are especially helpful. Standard flow:

1. Fork + branch (`feat:`, `fix:`, `docs:` conventional commit prefixes)
2. Add / adjust tests (`cargo test`)
3. Run linting (`cargo fmt`, `cargo clippy -- -D warnings`)
4. Open a PR referencing any related issue

See `SECURITY.md` for coordinated security disclosure guidelines.

## Planned Features

The following features are planned for future releases to enhance axum-gate's production readiness:

### Production Observability (v1.1.0)
- **Structured logging integration**: Comprehensive tracing spans with contextual metadata for all authentication operations
- **Prometheus metrics**: Built-in counters, histograms, and gauges for login attempts, JWT operations, authorization checks, and system health
- **Audit trail system**: Pluggable audit recorders for security compliance (file, database, structured logging)
- **Performance monitoring**: Request duration tracking, storage operation metrics, and system health indicators
- **Security metrics**: Brute force detection, rate limiting triggers, suspicious activity monitoring
- **Multiple backend support**: In-memory (development), Prometheus (production), OpenTelemetry (enterprise)

Feature flags: `metrics-prometheus`, `observability-full`

### Authentication Enhancements
- **Key rotation utilities**: Seamless JWT signing key rotation without global session invalidation
- **Bearer token Gate**: Header-based authentication for SPA and API clients

### Security & Compliance
- **Audit hooks**: Unified security event streaming for SIEM integration
- **IP-based restrictions**: Geographic and network-based access controls

All features will be backward-compatible and opt-in via feature flags. See [SECURITY.md](SECURITY.md) for additional security-focused planned features.

## Community & Support

- GitHub Issues: bug reports & feature discussions
- GitHub Discussions: design questions & architecture feedback
- Stack Overflow: tag `axum-gate`

## License

Licensed under the MIT License. See [LICENSE](LICENSE).

## Acknowledgments

Built on the shoulders of:
- [axum]
- [jsonwebtoken]
- [tokio]
- [SeaORM]
- [SurrealDB]
- The wider Rust async ecosystem

Thanks to all current & future contributors!

---

<div align="center">

Built with ❤️ by the Rust community

[Documentation](https://docs.rs/axum-gate) • [Examples](https://github.com/emirror-de/axum-gate/tree/main/examples) • [Changelog](CHANGELOG.md)

</div>

<!-- Reference Links -->
[axum]: https://github.com/tokio-rs/axum
[jsonwebtoken]: https://github.com/Keats/jsonwebtoken
[tokio]: https://tokio.rs
[SeaORM]: https://github.com/SeaQL/sea-orm
[SurrealDB]: https://surrealdb.com/
