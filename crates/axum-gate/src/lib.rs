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
//! ```rust,no_run
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
//!     use axum_gate::utils::external::jsonwebtoken::{DecodingKey, EncodingKey};
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
//! // Validate permissions at compile-time
//! axum_gate::validate_permissions!["read:api", "write:api", "admin:system"];
//!
//! // Use in policies
//! let policy = AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"));
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
//! ```rust,no_run
//! # #[cfg(feature = "storage-surrealdb")]
//! # {
//! use axum_gate::storage;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: surrealdb::Surreal<surrealdb::engine::any::Any> = todo!();
//! # let scope = storage::surrealdb::DatabaseScope::default();
//! let repo = Arc::new(storage::surrealdb::SurrealDbRepository::new(db, scope));
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ### SeaORM (Feature: `storage-seaorm`)
//! ```rust,no_run
//! # #[cfg(feature = "storage-seaorm")]
//! # {
//! use axum_gate::storage;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: sea_orm::DatabaseConnection = todo!();
//! let repo = Arc::new(storage::seaorm::SeaOrmRepository::new(&db));
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
//! - **Compile-time validation**: Use `validate_permissions!` macro to detect permission collisions at build time
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

mod application;
mod domain;
pub mod errors;
mod infrastructure;
mod ports;

/// Common types and functions for quick imports.
pub mod prelude {
    pub use crate::auth::{AccessPolicy, Account, Credentials, Group, Role};
    pub use crate::infrastructure::web::cookie_template::CookieTemplateBuilder;
    // Authentication middleware and builders.
    pub use crate::infrastructure::web::gate::{CookieGate, Gate};
}

/// Authentication types, policies, and account management.
pub mod auth {

    pub use crate::domain::entities::{Account, Credentials, Group, Role};
    pub use crate::domain::services::access_policy::AccessPolicy;
    pub use crate::domain::values::{PermissionId, Permissions};

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
/// use axum_gate::storage::TableNames;
/// # let db: surrealdb::Surreal<surrealdb::engine::any::Any> = todo!();
/// let scope = DatabaseScope {
///     table_names: TableNames::default(), // override if you want different table names
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
/// # let db: sea_orm::DatabaseConnection = todo!();
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
        MemoryAccountRepository, MemorySecretRepository,
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
    #[cfg(any(feature = "storage-surrealdb"))]
    pub use crate::infrastructure::repositories::TableNames;
}

/// Advanced / power‑user APIs.
///
/// This module exposes lower-level building blocks for developers who need to:
/// - Implement custom repositories or hashing backends
/// - Integrate with non-standard JWT or transport layers
/// - Build custom login handlers instead of the provided route handlers
/// - Perform runtime permission validation (dynamic permission sources)
/// - Implement custom middleware instead of (or in addition to) the built-in `Gate`
///
/// # Categories
///
/// ## 1. Role & Permission Modeling
/// - [`AccessHierarchy`]: Implement on your role enum to enable supervisor traversal
/// - [`AsPermissionName`]: Implement on enums / structured permission types to map to canonical strings
///
/// ## 2. Storage & Hashing Abstractions
/// - [`AccountRepository`], [`SecretRepository`]
/// - [`CredentialsVerifier`], [`HashingService`]
/// - [`Argon2Hasher`], [`HashedValue`]
///
/// ## 3. Authentication Workflow
/// - [`LoginService`], [`LoginResult`]
/// - [`Secret`], [`VerificationResult`]
///
/// ## 4. Permission Validation
/// - [`ApplicationValidator`]: Builder-style startup validation
/// - [`PermissionCollisionChecker`]: Detailed runtime collision/duplicate analysis
/// - [`ValidationReport`]
///
/// ## 5. JWT Integration
/// - [`JwtValidationService`], [`JwtValidationResult`] for custom middleware
/// - [`Codec`] for alternative token encodings
///
/// ## 6. When NOT to Use This
/// If you only:
/// - Protect routes with roles/groups/permissions
/// - Use built-in login/logout handlers
/// - Use provided backends
///
/// Then you likely just need `prelude`, `auth`, `jwt`, `storage`, and `http`.
///
/// # Stability Notice
/// These exports are lower-level and may evolve more rapidly. Previously exported internals
/// like `AccessScope` and raw hashing helpers (e.g. internal hashing constants) are intentionally
/// not re-exported to prevent accidental coupling to implementation details. Open an issue if you
/// have a legitimate use case for something removed here.
///
/// # Example: Custom Login Endpoint
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum_gate::advanced::{LoginService, CredentialsVerifier, AccountRepository, Codec};
/// use axum_gate::auth::{Credentials, Account, Role, Group};
/// use axum_gate::jwt::{RegisteredClaims, JwtClaims, JsonWebToken};
///
/// async fn custom_login<Creds, AccRepo, C>(
///     creds: Credentials<String>,
///     creds_repo: Arc<Creds>,
///     account_repo: Arc<AccRepo>,
///     codec: Arc<C>
/// ) -> Result<String, String>
/// where
///     Creds: CredentialsVerifier<uuid::Uuid>,
///     AccRepo: AccountRepository<Role, Group>,
///     C: Codec<Payload = JwtClaims<Account<Role, Group>>>,
/// {
///     let registered = RegisteredClaims::new("my-app", chrono::Utc::now().timestamp() as u64 + 3600);
///     let service = LoginService::<Role, Group>::new();
///     match service.authenticate(creds, registered, creds_repo, account_repo, codec).await {
///         axum_gate::advanced::LoginResult::Success(token) => Ok(token),
///         axum_gate::advanced::LoginResult::InvalidCredentials => Err("invalid credentials".into()),
///         axum_gate::advanced::LoginResult::InternalError(e) => Err(format!("internal error: {e}"))
///     }
/// }
/// ```
pub mod advanced {

    // Role & permission modeling
    pub use crate::domain::traits::{AccessHierarchy, AsPermissionName};

    // Core extension traits & integration points
    pub use crate::ports::Codec;
    pub use crate::ports::auth::{CredentialsVerifier, HashingService};
    pub use crate::ports::repositories::{AccountRepository, SecretRepository};

    // Authentication workflow (service + result)
    pub use crate::application::auth::{LoginResult, LoginService};

    // Permission validation utilities
    pub use crate::domain::services::permissions::validation::{
        ApplicationValidator, PermissionCollisionChecker, ValidationReport,
    };

    // Hashing & secrets
    pub use crate::domain::values::{Secret, VerificationResult};
    pub use crate::infrastructure::hashing::{Argon2Hasher, HashedValue};

    // JWT validation for custom middleware
    pub use crate::infrastructure::jwt::{JwtValidationResult, JwtValidationService};
}

/// Common utilities, helper types and external crate re-exports.
pub mod utils {

    pub use uuid::Uuid;

    /// External crate re-exports, convenient access to commonly used external types.
    pub mod external {
        pub use jsonwebtoken;
        pub use serde_json;
    }
}
