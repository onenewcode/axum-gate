# axum-gate

[![Crates.io](https://img.shields.io/crates/v/axum-gate.svg)](https://crates.io/crates/axum-gate)
[![Documentation](https://docs.rs/axum-gate/badge.svg)](https://docs.rs/axum-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/emirror-de/axum-gate/workflows/CI/badge.svg)](https://github.com/emirror-de/axum-gate/actions)

**Flexible, type-safe authentication and authorization library for Axum applications**

`axum-gate` provides production-ready JWT cookie authentication, hierarchical role and permission management, and a clean architecture designed for maintainability and testability. Built with modern Rust patterns and optimized for AI-assisted development workflows.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Architecture](#architecture)
- [Security](#security)
- [Configuration](#configuration)
- [Testing](#testing)
- [Performance](#performance)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

### Authentication & Authorization
- **JWT Cookie Authentication**: Secure, configurable token-based auth with proper cookie settings
- **Hierarchical Role System**: Supervisor/subordinate role relationships with automatic permission inheritance  
- **Permission Management**: Dense bitmap-powered permission sets for fast membership testing
- **Flexible Access Policies**: Combine role, permission, and group-based access control

### Storage & Backends
- **Multiple Storage Options**: In-memory (testing), SurrealDB, SeaORM support
- **Pluggable Architecture**: Separate account and secret storage with clean interfaces
- **Cross-Node Consistency**: Deterministic permission hashing for distributed deployments

### Security & Production Features
- **Secure Defaults**: Argon2 password hashing, secure JWT handling, proper cookie configuration
- **Input Validation**: Comprehensive validation at system boundaries with structured error responses
- **Rate Limiting**: Integration examples with tower middleware
- **Audit Logging**: Structured logging with correlation IDs and security events

### Developer Experience
- **Type Safety**: Full type safety with compile-time validation of roles and permissions
- **Comprehensive Testing**: Test utilities, property-based testing, and validation helpers
- **Clean Architecture**: Clear separation between domain, application, and infrastructure layers
- **AI-Friendly**: Explicit types, comprehensive error handling, and extensive documentation

## Installation

### Prerequisites

- **Rust**: 1.86.0 or later
- **Tokio**: Async runtime (automatically included)
- **Optional**: Database (SurrealDB or SeaORM-compatible database)

### Basic Installation

Add `axum-gate` to your `Cargo.toml`:

```toml
[dependencies]
axum-gate = "1.0.0"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

### With Storage Backends

For SurrealDB support:
```toml
[dependencies]
axum-gate = { version = "1.0.0", features = ["storage-surrealdb"] }
surrealdb = { version = "2", features = ["kv-mem"] }
```

For SeaORM support:
```toml
[dependencies]
axum-gate = { version = "1.0.0", features = ["storage-seaorm"] }
sea-orm = { version = "1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

### Feature Flags

| Feature | Description | Use Case |
|---------|-------------|----------|
| `storage-surrealdb` | SurrealDB repository implementation | NoSQL database backend |
| `storage-seaorm` | SeaORM repository implementation | SQL database backend |
| `insecure-fast-hash` | Reduced Argon2 preset for development | **Development only** - never enable in production |
| `prometheus` | Prometheus metrics integration | Production monitoring |
| `audit-logging` | Comprehensive audit trail logging | Compliance and security monitoring |

## Quick Start

### 1. Define Roles and Permissions

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
    Manager,
    Admin,
}

impl RoleDefinition for AppRole {
    type Permission = AppPermission;

    fn permissions(self) -> PermissionMask<Self::Permission> {
        use AppPermission::*;
        
        match self {
            Self::User => mask![ViewDashboard],
            Self::Manager => mask![ViewDashboard, ManageUsers, BillingRead],
            Self::Admin => mask![ViewDashboard, ManageUsers, BillingRead, BillingWrite],
        }
    }

    fn parents(self) -> &'static [Self] {
        match self {
            Self::User => &[],
            Self::Manager => &[Self::User],
            Self::Admin => &[Self::Manager],
        }
    }
}
```

### 2. Set Up Services and Middleware

```rust
use axum::{routing::get, Router, Extension};
use axum_gate::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt::init();

    // Set up repositories (use appropriate backend for production)
    let account_repo = Arc::new(InMemoryAccountRepository::default());
    let secret_repo = Arc::new(InMemorySecretRepository::default());

    // Create JWT codec with secure secret
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "dev-secret-change-in-production".to_string());
    let jwt_codec = Arc::new(JsonWebToken::new(jwt_secret.as_bytes()));

    // Authentication and authorization services  
    let authz_service = AuthorizationService::<AppRole>::new();
    let gate_layer = GateLayer::new(jwt_codec.clone(), authz_service);

    // Build application with protected routes
    let app = Router::new()
        .route("/", get(public_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/admin", get(admin_handler))
        .layer(gate_layer)
        .with_state(AppState {
            account_repo,
            secret_repo,
            jwt_codec,
        });

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Server running on http://127.0.0.1:3000");
    
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
struct AppState {
    account_repo: Arc<InMemoryAccountRepository<AppRole>>,
    secret_repo: Arc<InMemorySecretRepository>,
    jwt_codec: Arc<JsonWebToken<JwtClaims<Account<AppRole>>>>,
}
```

### 3. Create Protected Handlers

```rust
use axum::response::Json;
use serde_json::{json, Value};

// Public endpoint - no authentication required
async fn public_handler() -> Json<Value> {
    Json(json!({ "message": "Welcome to the public area!" }))
}

// Requires any authenticated user
async fn dashboard_handler(
    AuthenticatedAccount(account): AuthenticatedAccount<AppRole>
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "message": "Welcome to your dashboard!",
        "user_id": account.id,
        "role": account.role
    })))
}

// Requires admin role
async fn admin_handler(
    RequireRole(account): RequireRole<AppRole, { AppRole::Admin as u8 }>
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "message": "Admin panel access granted",
        "admin_id": account.id
    })))
}

// Custom error type for application
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,
    #[error("Access denied: insufficient permissions")]
    Forbidden,
    #[error("Internal server error")]
    Internal,
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Authentication required"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Access denied"),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        
        (status, Json(json!({ "error": message }))).into_response()
    }
}
```

To run this example:

```bash
# Set JWT secret (use a secure random value in production)
export JWT_SECRET="your-secure-jwt-secret-at-least-32-characters"

# Run the application  
cargo run

# Test the endpoints
curl http://127.0.0.1:3000/                 # Public access
curl http://127.0.0.1:3000/dashboard        # Requires authentication
curl http://127.0.0.1:3000/admin           # Requires admin role
```

## Usage Examples

### Web Application with Cookie Authentication

```rust
use axum_gate::cookie::{CookieTemplate, SameSite};

// Configure secure cookie settings for web applications
let gate = Gate::cookie("my-web-app", jwt_codec)
    .configure_cookie_template(|template| {
        template
            .name("auth_token")
            .http_only(true)
            .secure(true)  // Enable in production with HTTPS
            .same_site(SameSite::Strict)
            .max_age(Duration::hours(24))
            .path("/")
    })
    .with_policy(AccessPolicy::require_role(AppRole::User));
```

### API with Bearer Token Authentication

```rust
// Header-based authentication for REST APIs
let gate = Gate::bearer("my-api", jwt_codec)
    .with_policy(AccessPolicy::require_permission(AppPermission::ViewDashboard));

// Usage in handler
async fn api_handler(
    AuthenticatedAccount(account): AuthenticatedAccount<AppRole>,
    Json(request): Json<ApiRequest>,
) -> Result<Json<ApiResponse>, ApiError> {
    // Handler implementation
    todo!()
}
```

### Permission-Based Access Control

```rust
// Complex permission requirements
let policy = AccessPolicy::require_permission(AppPermission::ManageUsers)
    .and_require_role(AppRole::Manager)
    .or_require_role(AppRole::Admin);

let gate = Gate::cookie("admin-panel", jwt_codec)
    .with_policy(policy);
```

### Optional Authentication

```rust
// Public routes with optional user context
async fn optional_auth_handler(
    user: Option<AuthenticatedAccount<AppRole>>,
) -> Json<Value> {
    match user {
        Some(AuthenticatedAccount(account)) => {
            Json(json!({ "message": "Hello, authenticated user!", "user_id": account.id }))
        }
        None => {
            Json(json!({ "message": "Hello, anonymous user!" }))
        }
    }
}
```

## Architecture

`axum-gate` follows clean architecture principles with clear separation of concerns:

```
┌─────────────────────┐
│   Web Layer (Axum) │  ← HTTP extractors, middleware, response mappers
├─────────────────────┤
│  Application Layer  │  ← Login service, account provisioning, business logic  
├─────────────────────┤
│   Domain Layer      │  ← Role definitions, permission sets, session claims
├─────────────────────┤
│ Infrastructure Layer│  ← Repositories, password hashing, JWT encoding
└─────────────────────┘
```

### Key Components

#### Domain Layer
- **Role Definitions**: Type-safe role hierarchies with permission mapping
- **Permission Sets**: Efficient bitmap-based permission storage and checking
- **Account Models**: Core user account and authentication data structures

#### Application Layer  
- **Authentication Service**: Login/logout flows, session management
- **Authorization Service**: Permission evaluation and access control
- **Account Service**: User provisioning and account management

#### Infrastructure Layer
- **Repository Traits**: Abstract storage interfaces for accounts and secrets
- **Storage Implementations**: In-memory, SurrealDB, and SeaORM backends
- **Security Services**: Password hashing, JWT encoding/decoding

#### Web Layer
- **Gate Middleware**: Request authentication and authorization
- **Extractors**: Type-safe extraction of authenticated user context
- **Error Handling**: Structured error responses with proper HTTP status codes

## Security

### Authentication Security

- **Password Hashing**: Uses Argon2id with secure parameters
- **JWT Security**: HMAC-SHA256 signing with configurable expiration
- **Session Management**: Secure cookie configuration with proper flags

### Security Configuration

```rust
// Production JWT configuration
let jwt_options = JsonWebTokenOptions {
    enc_key: EncodingKey::from_secret(&jwt_secret),
    dec_key: DecodingKey::from_secret(&jwt_secret),
    header: Some(Header::new(Algorithm::HS256)),
    validation: Some(Validation {
        validate_exp: true,
        validate_aud: false,
        validate_nbf: true,
        leeway: 60, // 1 minute clock skew tolerance
        ..Default::default()
    }),
};

// Secure cookie template for production
let cookie_template = CookieTemplate::build()
    .name("auth_token")
    .http_only(true)
    .secure(true)        // Requires HTTPS
    .same_site(SameSite::Strict)
    .max_age(Duration::hours(8))
    .path("/")
    .build();
```

### Security Best Practices

#### JWT Secret Management
```bash
# Generate a secure JWT secret (32+ bytes)
openssl rand -base64 32

# Set via environment variable
export JWT_SECRET="<REDACTED:JWT_SECRET>"

# Or use a secret management system
export JWT_SECRET_FILE="/run/secrets/jwt_secret"
```

#### Input Validation
```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
struct LoginRequest {
    #[validate(length(min = 3, max = 50))]
    username: String,
    
    #[validate(length(min = 8))]
    password: String,
}

async fn login_handler(
    State(app_state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    // Validate input before processing
    request.validate().map_err(AuthError::ValidationError)?;
    
    // Process login...
    todo!()
}
```

#### Rate Limiting Integration
```rust
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

// Apply rate limiting to login endpoints
let governor_conf = Box::new(
    GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(10)
        .finish()
        .unwrap()
);

let app = Router::new()
    .route("/login", post(login_handler))
    .layer(ServiceBuilder::new().layer(GovernorLayer { config: governor_conf }))
    .layer(gate_layer);
```

### Security Audit Status

**Security Dependencies**: All dependencies are regularly audited using `cargo audit`. Any temporary advisory exclusions are documented in `deny.toml` with clear justification and resolution timelines.

**Cryptographic Review**: Password hashing and JWT implementations use well-established libraries (`argon2`, `jsonwebtoken`) with secure defaults.

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `JWT_SECRET` | JWT signing secret (32+ bytes) | None | Yes |
| `JWT_EXPIRY_HOURS` | JWT token lifetime in hours | `24` | No |
| `COOKIE_SECURE` | Enable secure cookie flag | `true` | No |
| `COOKIE_DOMAIN` | Cookie domain restriction | None | No |
| `PASSWORD_HASH_COST` | Argon2 cost parameter | `19` (production) | No |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed origins | `*` | No |

### Database Configuration

#### SurrealDB
```toml
# Cargo.toml
[dependencies]
axum-gate = { version = "1.0.0", features = ["storage-surrealdb"] }
surrealdb = { version = "2", features = ["kv-rocksdb"] }
```

```rust
use axum_gate::repositories::surrealdb::SurrealDbAccountRepository;

// Configure SurrealDB repository
let db = Surreal::new::<RocksDb>("path/to/database").await?;
db.use_ns("myapp").use_db("auth").await?;

let account_repo = Arc::new(SurrealDbAccountRepository::new(db));
```

#### SeaORM (PostgreSQL, MySQL, SQLite)
```toml
# Cargo.toml  
[dependencies]
axum-gate = { version = "1.0.0", features = ["storage-seaorm"] }
sea-orm = { version = "1", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

```rust
use axum_gate::repositories::seaorm::SeaOrmAccountRepository;

// Configure PostgreSQL connection
let database_url = std::env::var("DATABASE_URL")?;
let db = Database::connect(database_url).await?;

let account_repo = Arc::new(SeaOrmAccountRepository::new(db));
```

## Testing

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum_gate::testing::*;
    
    #[tokio::test]
    async fn test_user_authentication() {
        let account_repo = Arc::new(InMemoryAccountRepository::default());
        let secret_repo = Arc::new(InMemorySecretRepository::default());
        
        // Create test account
        let account = create_test_account("testuser", AppRole::User).await;
        account_repo.insert(account.clone()).await.unwrap();
        
        // Test authentication
        let auth_service = AuthenticationService::new(account_repo, secret_repo);
        let result = auth_service
            .authenticate("testuser", "password123")
            .await;
            
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_permission_hierarchy() {
        let admin_permissions = AppRole::Admin.permissions();
        let user_permissions = AppRole::User.permissions();
        
        // Admin should have all user permissions
        assert!(admin_permissions.contains_all(&user_permissions));
        assert!(admin_permissions.contains(AppPermission::ManageUsers));
    }
}
```

### Integration Testing

```rust
#[tokio::test]
async fn test_protected_endpoint() {
    use axum_test::TestServer;
    
    let app = create_test_app().await;
    let server = TestServer::new(app).unwrap();
    
    // Test unauthorized access
    let response = server.get("/admin").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    
    // Test authorized access
    let token = create_test_jwt(AppRole::Admin).await;
    let response = server
        .get("/admin")
        .add_cookie(Cookie::new("auth_token", token))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}
```

### Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_permission_mask_operations(
        permissions in prop::collection::vec(any::<AppPermission>(), 0..10)
    ) {
        let mask1 = permissions.iter().collect::<PermissionMask<_>>();
        let mask2 = permissions.iter().collect::<PermissionMask<_>>();
        
        // Test idempotent operations
        assert_eq!(mask1.union(&mask2), mask1);
        assert_eq!(mask1.intersection(&mask2), mask1);
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with specific features
cargo test --features storage-surrealdb

# Run integration tests only
cargo test --test integration

# Run with coverage
cargo tarpaulin --out Html
```

## Performance

### Benchmarks

`axum-gate` includes comprehensive benchmarks for critical paths:

```bash
# Run performance benchmarks
cargo bench

# Profile authentication flow
cargo bench --bench auth_flow

# Profile permission checking
cargo bench --bench permission_check
```

### Performance Characteristics

- **Permission Checking**: O(1) bitmap operations for permission tests
- **Role Resolution**: O(log n) hierarchy traversal with caching
- **JWT Operations**: ~10μs encode/decode on modern hardware  
- **Memory Usage**: ~100 bytes per account in memory repositories

### Optimization Tips

#### Permission Set Optimization
```rust
// Use const assertions to validate permissions at compile time
const _: () = assert!(AppRole::Admin.permissions().len() > 0);

// Pre-compute permission masks for hot paths
lazy_static! {
    static ref ADMIN_PERMISSIONS: PermissionMask<AppPermission> = 
        AppRole::Admin.permissions();
}
```

#### Caching Strategies
```rust
use std::sync::Arc;
use tokio::sync::RwLock;

// Cache frequently accessed permissions
#[derive(Clone)]
struct CachedAuthorizationService {
    cache: Arc<RwLock<HashMap<UserId, PermissionMask<AppPermission>>>>,
    inner: AuthorizationService<AppRole>,
}

impl CachedAuthorizationService {
    async fn check_permission(&self, user_id: UserId, permission: AppPermission) -> bool {
        // Check cache first, fall back to computation
        let cache = self.cache.read().await;
        if let Some(permissions) = cache.get(&user_id) {
            return permissions.contains(permission);
        }
        drop(cache);
        
        // Compute and cache
        let permissions = self.inner.get_permissions(user_id).await;
        self.cache.write().await.insert(user_id, permissions.clone());
        permissions.contains(permission)
    }
}
```

## Examples

The `examples/` directory contains complete, runnable examples:

| Example | Description | Features |
|---------|-------------|----------|
| [`simple-usage`](examples/simple-usage/) | Basic authentication with HTML forms | Cookie auth, role-based access |
| [`distributed`](examples/distributed/) | Multi-node deployment patterns | Consistent permission hashing |
| [`custom-roles`](examples/custom-roles/) | Advanced role and permission modeling | Custom hierarchies, validation |
| [`surrealdb`](examples/surrealdb/) | SurrealDB storage backend | NoSQL integration, migrations |
| [`sea-orm`](examples/sea-orm/) | SeaORM database integration | SQL databases, type-safe queries |
| [`rate-limiting`](examples/rate-limiting/) | Rate limiting integration | Tower middleware, governor |
| [`permission-validation`](examples/permission-validation/) | Runtime permission checking | Test utilities, validation |
| [`prometheus`](examples/prometheus/) | Metrics and monitoring | Prometheus integration, dashboards |

### Running Examples

```bash
# Basic usage example
cargo run --example simple-usage

# SurrealDB example
cargo run --example surrealdb --features storage-surrealdb

# All features example
cargo run --example distributed --all-features

# With environment configuration
JWT_SECRET="dev-secret" cargo run --example simple-usage
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/emirror-de/axum-gate.git
   cd axum-gate
   ```

2. **Install development dependencies**
   ```bash
   # Install Rust toolchain
   rustup install stable
   rustup component add rustfmt clippy
   
   # Install additional tools
   cargo install cargo-audit cargo-tarpaulin
   ```

3. **Run the development workflow**
   ```bash
   # Format code
   cargo fmt
   
   # Run lints
   cargo clippy -- -D warnings
   
   # Run tests
   cargo test
   
   # Security audit
   cargo audit
   
   # Check all feature combinations
   cargo test --all-features
   ```

### Code Quality Standards

- **Formatting**: Use `cargo fmt` with default settings
- **Linting**: All `clippy` warnings must be resolved
- **Testing**: Maintain >90% test coverage
- **Documentation**: Document all public APIs with examples
- **Security**: No `unwrap()`/`expect()` in production code paths

### Pull Request Process

1. **Create feature branch**: `git checkout -b feat/new-feature`
2. **Implement changes**: Follow existing code patterns and style
3. **Add tests**: Cover both success and error paths
4. **Update documentation**: Include examples for new features  
5. **Verify quality**: Run full test suite and linting
6. **Submit PR**: Include clear description and link related issues

### Reporting Issues

- **Bug Reports**: Use the bug report template with reproduction steps
- **Feature Requests**: Describe use case and proposed API design
- **Security Issues**: Follow our [Security Policy](SECURITY.md)

## Minimum Supported Rust Version (MSRV)

**Current MSRV**: Rust 1.86.0

**MSRV Policy**:
- MSRV increases only occur in minor or major releases, never patches
- We support the latest 6 months of Rust releases when practical  
- MSRV changes are documented in the changelog with justification
- CI tests against MSRV to prevent accidental breakage

## Versioning & Compatibility

`axum-gate` follows [Semantic Versioning](https://semver.org/):

- **Patch (1.0.x)**: Bug fixes, performance improvements, documentation
- **Minor (1.x.0)**: New features, backward-compatible API additions  
- **Major (x.0.0)**: Breaking changes with migration guide

### API Stability Promise

- Public APIs are stable within major versions
- Internal modules may change in minor releases
- Deprecated APIs include migration guidance and timeline
- Breaking changes are minimized and clearly documented

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and release timeline:

- **v1.1.0**: Enhanced observability, Prometheus metrics, audit logging
- **v1.2.0**: Advanced authentication (OAuth2, SAML), session management  
- **v2.0.0**: Performance optimizations, API refinements, additional storage backends

## Community & Support

- **Documentation**: [docs.rs/axum-gate](https://docs.rs/axum-gate)
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Design questions and community support
- **Stack Overflow**: Tag questions with `axum-gate`

## Security

For security-related concerns, please see our [Security Policy](SECURITY.md).

**Coordinated Disclosure**: Email security issues to <REDACTED:EMAIL> rather than filing public issues.

## License

Licensed under the [MIT License](LICENSE).

## Acknowledgments

Built on the foundation of excellent Rust crates:

- [axum](https://github.com/tokio-rs/axum) - Web application framework
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT implementation  
- [tokio](https://tokio.rs) - Async runtime
- [argon2](https://github.com/RustCrypto/password-hashes) - Password hashing
- [roaring](https://github.com/RoaringBitmap/roaring-rs) - Efficient bitmaps

Special thanks to all [contributors](https://github.com/emirror-de/axum-gate/contributors) who have helped improve this project!

---

<div align="center">

**[Documentation](https://docs.rs/axum-gate)** • **[Examples](examples/)** • **[Changelog](CHANGELOG.md)** • **[Roadmap](ROADMAP.md)**

Built with ❤️ by the Rust community

</div>