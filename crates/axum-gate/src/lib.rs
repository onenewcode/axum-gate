#![deny(missing_docs)]

//! # axum-gate
//!
//! Fully customizable role-based JWT cookie authentication for axum, designed for both single nodes and distributed systems.
//!
//! ## Key Features
//!
//! - **Role-based access control** - Hierarchical roles with customizable permissions
//! - **JWT cookie authentication** - Secure, stateless authentication
//! - **Multiple storage backends** - In-memory, SurrealDB, SeaORM support
//! - **Permission system** - Static validation with collision detection
//! - **Zero-synchronization permissions** - Deterministic hashing eliminates sync needs
//! - **Distributed system ready** - Separate account/secret storage for enhanced security
//! - **Pre-built handlers** - Login/logout endpoints included
//!
//! ## Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_gate::prelude::*;
//! use axum_gate::{storage, jwt};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Set up storage
//!     let account_repo = Arc::new(storage::MemoryAccountRepository::<Role, Group>::default());
//!     let secret_repo = Arc::new(storage::MemorySecretRepository::default());
//!
//!     // Create JWT codec with persistent key for production
//!     use axum_gate::integrations::jsonwebtoken::{DecodingKey, EncodingKey};
//!     let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-key".to_string());
//!     let options = jwt::JsonWebTokenOptions {
//!         enc_key: EncodingKey::from_secret(secret.as_bytes()),
//!         dec_key: DecodingKey::from_secret(secret.as_bytes()),
//!         header: None,
//!         validation: None,
//!     };
//!     let jwt_codec = Arc::new(jwt::JsonWebToken::<jwt::JwtClaims<Account<Role, Group>>>::new_with_options(options));
//!
//!     // Protect routes with role-based access
//!     let app = Router::<()>::new()
//!         .route("/admin", get(admin_handler))
//!         .layer(
//!             Gate::cookie("my-app", jwt_codec)
//!                 .with_policy(AccessPolicy::require_role(Role::Admin))
//!         );
//! }
//!
//! async fn admin_handler() -> &'static str { "Admin access granted!" }
//! ```
//!
//! ## Access Control
//!
//! ### Role-Based
//! ```rust
//! use axum_gate::auth::{AccessPolicy, Role, Group};
//!
//! // Single role
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//!
//! // Multiple roles
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin).or_require_role(Role::Moderator);
//!
//! // Hierarchical (role + supervisors)
//! let policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
//! ```
//!
//! ### Group-Based
//! ```rust
//! use axum_gate::auth::{AccessPolicy, Group, Role};
//!
//! let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"))
//!     .or_require_group(Group::new("management"));
//! ```
//!
//! ### Permission-Based
//! ```rust
//! use axum_gate::auth::{AccessPolicy, PermissionId, Role, Group};
//!
//! // Validate permissions at test-time (checks for hash collisions)
//! axum_gate::validate_permissions!["read:api", "write:api", "admin:system"];
//!
//! // Use in policies
//! let policy = AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"));
//! ```
//!
//! ### Convenient Login Check
//! ```rust
//! use axum_gate::prelude::*;
//! use axum_gate::{jwt, auth};
//! use std::sync::Arc;
//!
//! # let jwt_codec = Arc::new(jwt::JsonWebToken::<jwt::JwtClaims<auth::Account<auth::Role, auth::Group>>>::default());
//! // Allow any authenticated user (equivalent to all roles: User, Reporter, Moderator, Admin)
//! let gate = Gate::cookie::<_, auth::Role, auth::Group>("my-app", jwt_codec)
//!     .require_login()  // Convenience method for any logged-in user
//!     .configure_cookie_template(|tpl| tpl.name("auth-token"));
//! ```
//!
//! ### Nested Enum Permissions
//! ```rust
//! use axum_gate::advanced::AsPermissionName;
//! use axum_gate::auth::Permissions;
//!
//! #[derive(Debug, Clone, PartialEq)]
//! enum ApiPermission {
//!     Read,
//!     Write,
//!     Delete,
//! }
//!
//! #[derive(Debug, Clone, PartialEq)]
//! enum Permission {
//!     Api(ApiPermission),
//!     System(String),
//! }
//!
//! impl AsPermissionName for Permission {
//!     fn as_permission_name(&self) -> String {
//!         match self {
//!             Permission::Api(api) => format!("api:{:?}", api).to_lowercase(),
//!             Permission::System(sys) => format!("system:{}", sys),
//!         }
//!     }
//! }
//!
//! // Usage - convert to string representations first
//! let permissions = Permissions::from_iter([
//!     "api:read",
//!     "system:health",
//! ]);
//! ```
//!
//! ### Anonymous Optional User Context
//!
//! For routes that should never be blocked by the gate but may take advantage of
//! authenticated context when present, configure a gate with
//! [`CookieGate::allow_anonymous_with_optional_user`](crate::prelude::CookieGate::allow_anonymous_with_optional_user).
//!
//! Behavior:
//! - No authentication or authorization policy is enforced (all requests pass through)
//! - Inserts `Option<Account<R, G>>` and `Option<RegisteredClaims>` into request extensions
//! - These options are `Some(..)` only if a valid auth cookie / JWT was provided
//! - Handlers must perform any role / group / permission checks manually
//!
//! This mode is ideal for:
//! - Public pages that personalize when the user is logged in
//! - Gradual adoption of protected routes
//! - Soft-auth scenarios (e.g., feature flags for signed-in users)
//!
//! ```rust
//! use axum::{routing::get, Router, extract::Extension};
//! use axum_gate::prelude::*;
//! use axum_gate::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
//! use std::sync::Arc;
//!
//! async fn homepage(
//!     Extension(user_opt): Extension<Option<Account<Role, Group>>>,
//!     Extension(claims_opt): Extension<Option<RegisteredClaims>>,
//! ) -> String {
//!     if let (Some(user), Some(claims)) = (user_opt, claims_opt) {
//!         format!("Welcome back {} (token expires at {})", user.user_id, claims.expiration_time)
//!     } else {
//!         "Welcome anonymous visitor".into()
//!     }
//! }
//!
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let app = Router::<()>::new()
//!     .route("/", get(homepage))
//!     .layer(
//!         Gate::cookie("my-app", jwt_codec)
//!             .allow_anonymous_with_optional_user()
//!     );
//! ```
//!
//! **SECURITY**: Do not use this mode for sensitive endpoints; apply a policy
//! via `with_policy(...)` or use `require_login()` when enforcement is required.
//!
//! ## Account Management
//!
//! ```rust
//! use axum_gate::auth::{AccountInsertService, Role, Group, Permissions};
//! use axum_gate::storage::{MemoryAccountRepository, MemorySecretRepository};
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! # let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! # let secret_repo = Arc::new(MemorySecretRepository::default());
//! // Create account with roles and permissions
//! let account = AccountInsertService::insert("user@example.com", "password")
//!     .with_roles(vec![Role::User])
//!     .with_groups(vec![Group::new("staff")])
//!     .with_permissions(Permissions::from_iter(["read:profile"]))
//!     .into_repositories(account_repo, secret_repo)
//!     .await;
//! # });
//! ```
//!
//! ## Storage Backends
//!
//! ### In-Memory (Development)
//! ```rust
//! use axum_gate::{storage, auth};
//! use std::sync::Arc;
//!
//! let account_repo = Arc::new(storage::MemoryAccountRepository::<auth::Role, auth::Group>::default());
//! let secret_repo = Arc::new(storage::MemorySecretRepository::default());
//! ```
//!
//! ### SurrealDB (Feature: `storage-surrealdb`)
//! ```rust
//! # #[cfg(feature="storage-surrealdb")]
//! # {
//! use axum_gate::storage::surrealdb::{DatabaseScope, SurrealDbRepository};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: surrealdb::Surreal<surrealdb::engine::any::Any> = todo!(); // In real code: surrealdb::Surreal::new(...).await
//! # let scope = DatabaseScope::default();
//! let repo = Arc::new(SurrealDbRepository::new(db, scope));
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ### SeaORM (Feature: `storage-seaorm`)
//! ```rust
//! # #[cfg(feature="storage-seaorm")]
//! # {
//! use axum_gate::storage::seaorm::{SeaOrmRepository, models};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: sea_orm::DatabaseConnection = todo!(); // In real code: sea_orm::Database::connect(...).await
//! let repo = Arc::new(SeaOrmRepository::new(&db));
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Authentication Handlers
//!
//! The crate provides pre-built [`login`](auth::login) and [`logout`](auth::logout) handlers
//! for common authentication workflows. These handlers integrate with your storage backends
//! and JWT configuration to provide secure authentication endpoints. For complete implementation
//! examples with dependency injection and routing setup, see the `examples` folder in the
//! repository.
//!
//! ## User Data in Handlers
//!
//! ```rust
//! use axum::extract::Extension;
//! use axum_gate::auth::{Account, Role, Group};
//! use axum_gate::jwt::RegisteredClaims;
//!
//! async fn profile_handler(
//!     Extension(user): Extension<Account<Role, Group>>,
//!     Extension(claims): Extension<RegisteredClaims>,
//! ) -> String {
//!     format!(
//!         "Hello {}, roles: {:?}, issued at: {}, expires: {}",
//!         user.user_id, user.roles, claims.issued_at_time, claims.expiration_time
//!     )
//! }
//! ```
//!
//! ## Security Best Practices
//!
//! ### Cookie Security
//! - **Use secure defaults**: Start with `CookieTemplateBuilder::recommended()` which provides secure defaults (HTTPS-only, HttpOnly, SameSite=Strict in production; relaxed settings in debug builds for localhost development)
//! - **HTTPS enforcement**: Always use `secure(true)` cookies in production environments
//! - **XSS protection**: Enable `http_only(true)` to prevent client-side script access to auth cookies
//! - **CSRF mitigation**: Use `SameSite::Strict` for sensitive operations, `SameSite::Lax` for cross-site navigation needs
//! - **Cookie naming**: Use descriptive, non-sensitive cookie names (consider `__Host-` prefix for enhanced security)
//!
//! ### JWT Security
//! - **Appropriate expiration**: Set reasonable JWT expiration times based on your security requirements
//! - **Persistent signing keys**: Use stable, high-entropy JWT signing keys (≥32 bytes) in production - avoid the random default
//! - **Key rotation**: Implement periodic key rotation strategies for enhanced security
//!
//! ### Permission System
//! - **Test-time validation**: Use `validate_permissions!` macro to detect permission collisions during testing
//! - **Runtime validation**: Implement `PermissionCollisionChecker` for dynamic permission sets from config/database
//! - **Principle of least privilege**: Grant minimal necessary permissions and use specific role/group combinations
//!
//! ### General Security
//! - **Rate limiting**: Implement rate limiting on authentication endpoints to prevent brute force attacks (see `examples/rate-limiting` for implementation)
//! - **Input validation**: Validate and limit input sizes (usernames, passwords) to prevent resource exhaustion
//! - **Monitoring**: Log authentication events and monitor for suspicious patterns
//!
//! ## JWT Key Management
//!
//! WARNING: The default `JsonWebToken` regenerates a random signing key per instance (invalidating previously issued tokens). For any production, multi-instance, or restart-persistent environment, supply a persistent key via `JsonWebTokenOptions`; see [`JsonWebToken`](crate::jwt::JsonWebToken) docs for details and examples.
//!
//!
//! ## Timing Attack Protection
//!
//! This crate includes built-in protection against timing attacks in authentication:
//!
//! - **Constant-time credential verification**: Uses the `subtle` crate for constant-time operations
//! - **Always performs password verification**: Even for non-existent users, using dummy hashes
//! - **Unified error responses**: Returns `InvalidCredentials` for both wrong passwords and non-existent users
//! - **Database-agnostic protection**: Applied to all storage backends (Memory, SurrealDB, SeaORM)
//!
//! These protections prevent attackers from enumerating valid usernames through timing differences
//! in the authentication process. The login service now takes approximately the same time whether
//! a user exists or not, making timing-based user enumeration attacks infeasible.

pub mod advanced;
pub(crate) mod application;
pub(crate) mod domain;
pub mod errors;
pub(crate) mod infrastructure;
pub(crate) mod ports;

/// Common types and functions for quick imports.
pub mod prelude {
    pub use crate::auth::{AccessPolicy, Account, Credentials, Group, Role};
    pub use crate::infrastructure::web::cookie_template::CookieTemplateBuilder;
    // Authentication middleware and builders.
    pub use crate::infrastructure::web::gate::{Gate, cookie::CookieGate};
}

/// Authentication types, policies, and account management.
pub mod auth {

    pub use crate::domain::entities::{Account, Credentials, Group, Role};
    pub use crate::domain::services::access_policy::AccessPolicy;
    pub use crate::domain::values::{
        PermissionId, PermissionMapping, PermissionMappingError, Permissions, StaticTokenAuthorized,
    };

    // Account creation and management.
    pub use crate::application::accounts::{AccountDeleteService, AccountInsertService};

    // Login and logout route handlers.
    pub use crate::infrastructure::web::route_handlers::{login, logout};
}

/// JWT creation, validation, and claims management.
pub mod jwt {

    pub use crate::infrastructure::jwt::{
        JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims,
    };
}

/// Cookie handling and HTTP types.
pub mod http {

    pub use axum_extra::extract::cookie::CookieJar;
    pub use cookie::{self, SameSite};

    // Cookie duration type.
    pub use cookie::time::Duration;
}

/// Storage backends for accounts (roles / groups / permissions) and authentication secrets.
///
/// Available backends (enable the feature flags you need):
/// - memory (default, no feature): Fast & ephemeral. Use for tests and local development only.
/// - surrealdb (feature: `storage-surrealdb`): SurrealDB (KV/SQL hybrid). Customize tables / namespace / database.
/// - seaorm (feature: `storage-seaorm`): Any SQL database supported by SeaORM. Use provided entity models for schema creation.
///
/// Quick start (memory):
/// ```rust
/// use axum_gate::{storage, auth};
/// use std::sync::Arc;
/// let accounts = Arc::new(storage::MemoryAccountRepository::<auth::Role, auth::Group>::default());
/// let secrets  = Arc::new(storage::MemorySecretRepository::default());
/// ```
///
/// SurrealDB (feature `storage-surrealdb`):
/// ```rust,no_run
/// # #[cfg(feature="storage-surrealdb")]
/// # {
/// use axum_gate::storage::surrealdb::{DatabaseScope, SurrealDbRepository};
/// use axum_gate::storage::TableName;
/// # let db: surrealdb::Surreal<surrealdb::engine::any::Any> = todo!(); // In real code: surrealdb::Surreal::new(...).await
/// let scope = DatabaseScope {
///     accounts: TableName::AxumGateAccounts.to_string(),
///     credentials: TableName::AxumGateCredentials.to_string(),
///     permission_mappings: TableName::AxumGatePermissionMappings.to_string(),
///     namespace: "axum-gate".into(),
///     database: "axum-gate".into(),
/// };
/// let repo = SurrealDbRepository::new(db, scope);
/// # }
/// ```
///
/// SeaORM (feature `storage-seaorm`):
/// ```rust,no_run
/// # #[cfg(feature="storage-seaorm")]
/// # {
/// use axum_gate::storage::seaorm::{SeaOrmRepository, models};
/// # let db: sea_orm::DatabaseConnection = todo!(); // In real code: sea_orm::Database::connect(...).await
/// // Use models::account::Entity & models::credentials::Entity in migrations
/// let repo = SeaOrmRepository::new(&db);
/// # }
/// ```
///
/// All backends implement:
/// - [`AccountRepository`](crate::advanced::AccountRepository)
/// - [`SecretRepository`](crate::advanced::SecretRepository)
/// - [`CredentialsVerifier`](crate::advanced::CredentialsVerifier)
///
/// Security: Every backend performs constant-time credential verification (dummy hash for non‑existent users) to reduce timing side channel risk.
pub mod storage {
    pub use crate::infrastructure::repositories::memory::{
        MemoryAccountRepository, MemoryPermissionMappingRepository, MemorySecretRepository,
    };

    #[cfg(feature = "storage-surrealdb")]
    /// SurrealDB storage backend (enable the `storage-surrealdb` feature).
    pub mod surrealdb {
        pub use crate::infrastructure::repositories::surrealdb::{
            DatabaseScope, SurrealDbRepository,
        };
    }

    #[cfg(feature = "storage-seaorm")]
    /// SeaORM storage backend (enable the `storage-seaorm` feature).
    pub mod seaorm {
        pub use crate::infrastructure::repositories::sea_orm::{SeaOrmRepository, models};
    }

    // Re-export for SurrealDB table / namespace customization and (optionally) other DB backends.
    #[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
    pub use crate::infrastructure::repositories::TableName;
}

/// External crate re-exports, convenient access to commonly used external types.
pub mod integrations {
    pub use jsonwebtoken;
    #[cfg(feature = "prometheus")]
    pub use prometheus;
    pub use serde_json;
    pub use uuid::Uuid;
}

/// Audit logging utilities (feature: `audit-logging`).
#[cfg(feature = "audit-logging")]
pub use crate::infrastructure::audit;
