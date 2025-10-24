#![deny(missing_docs)]
//#![deny(clippy::unwrap_used)]
//#![deny(clippy::expect_used)]

//! # axum-gate
//!
//! Role-based JWT cookie authentication for axum applications, supporting both single nodes
//! and distributed systems with multiple storage backends.
//!
//! ## Key Features
//!
//! - **Role-based access control** - Hierarchical roles with supervisor inheritance
//! - **Group-based access control** - Organize users by teams, departments, or projects
//! - **Permission system** - Fine-grained permissions with deterministic hashing
//! - **JWT cookie authentication** - Secure, stateless authentication with customizable cookies
//! - **Multiple storage backends** - In-memory, SurrealDB, SeaORM support
//! - **Distributed system ready** - Zero-synchronization permission system
//! - **Pre-built handlers** - Login/logout endpoints with timing attack protection
//! - **Security by default** - Secure cookie templates and comprehensive input validation
//!
//! ## Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_gate::prelude::*;
//! use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims, JsonWebTokenOptions};
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::accounts::Account;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Set up storage
//!     let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//!     let secret_repo = Arc::new(MemorySecretRepository::default());
//!
//!     // Create JWT codec with persistent key for production
//!     let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-key".to_string());
//!     let options = JsonWebTokenOptions {
//!         enc_key: jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
//!         dec_key: jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
//!         header: None,
//!         validation: None,
//!     };
//!     let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(options));
//!
//!     // Protect routes with role-based access
//!     let app = Router::<()>::new()
//!         .route("/admin", get(admin_handler))
//!         .layer(
//!             Gate::cookie::<_, Role, Group>("my-app", jwt_codec)
//!                 .with_policy(AccessPolicy::require_role(Role::Admin))
//!                 .configure_cookie_template(|tpl| tpl.name("auth-token"))
//!         );
//! }
//!
//! async fn admin_handler() -> &'static str { "Admin access granted!" }
//! ```
//!
//! ## Access Control
//!
//! ### Role-Based Access
//! ```rust
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::prelude::{Role, Group};
//!
//! // Single role requirement
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//!
//! // Multiple role options
//! let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_role(Role::Moderator);
//!
//! // Hierarchical access (role + all supervisor roles)
//! let policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
//! ```
//!
//! ### Group-Based Access
//! ```rust
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::prelude::{Role, Group};
//!
//! let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"))
//!     .or_require_group(Group::new("management"));
//! ```
//!
//! ### Permission-Based Access
//! ```rust
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::permissions::PermissionId;
//! use axum_gate::prelude::{Role, Group};
//!
//! // Validate permissions at compile-time (checks for hash collisions)
//! axum_gate::validate_permissions!["read:api", "write:api", "admin:system"];
//!
//! // Use in access policies
//! let policy = AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"));
//! ```
//!
//! ### Convenient Login Check
//! ```rust
//! use axum_gate::prelude::*;
//! use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims};
//! use axum_gate::accounts::Account;
//! use std::sync::Arc;
//!
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! // Allow any authenticated user (all roles: User, Reporter, Moderator, Admin)
//! let gate = Gate::cookie::<_, Role, Group>("my-app", jwt_codec)
//!     .require_login()  // Convenience method for any logged-in user
//!     .configure_cookie_template(|tpl| tpl.name("auth-token"));
//! ```
//!
//! ### Optional User Context (Anonymous Access)
//!
//! For routes that should never be blocked but may use authenticated context when present:
//!
//! ```rust
//! use axum::{routing::get, Router, extract::Extension};
//! use axum_gate::prelude::*;
//! use axum_gate::codecs::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};
//! use axum_gate::accounts::Account;
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
//!         Gate::cookie::<_, Role, Group>("my-app", jwt_codec)
//!             .allow_anonymous_with_optional_user()
//!     );
//! ```
//!
//! ## Account Management
//!
//! ```rust
//! use axum_gate::accounts::{AccountInsertService, Account};
//! use axum_gate::permissions::Permissions;
//! use axum_gate::prelude::{Role, Group};
//! use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! # let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! # let secret_repo = Arc::new(MemorySecretRepository::default());
//! // Create account with roles, groups, and permissions
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
//! use axum_gate::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use axum_gate::prelude::{Role, Group};
//! use std::sync::Arc;
//!
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::default());
//! ```
//!
//! ### SurrealDB (Feature: `storage-surrealdb`)
//! ```rust
//! # #[cfg(feature="storage-surrealdb")]
//! # {
//! use axum_gate::repositories::surrealdb::{DatabaseScope, SurrealDbRepository};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: surrealdb::Surreal<surrealdb::engine::any::Any> = todo!();
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
//! use axum_gate::repositories::sea_orm::{SeaOrmRepository, models};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let db: sea_orm::DatabaseConnection = todo!();
//! let repo = Arc::new(SeaOrmRepository::new(&db));
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Authentication Handlers
//!
//! Pre-built [`route_handlers::login`] and [`route_handlers::logout`] handlers integrate with
//! your storage backends and JWT configuration. See examples in the repository for complete
//! implementation patterns with dependency injection and routing setup.
//!
//! ## User Data in Handlers
//!
//! ```rust
//! use axum::extract::Extension;
//! use axum_gate::accounts::Account;
//! use axum_gate::codecs::jwt::RegisteredClaims;
//! use axum_gate::prelude::{Role, Group};
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
//! ## Security Features
//!
//! ### Cookie Security
//! - **Secure defaults**: [`cookie_template::CookieTemplateBuilder::recommended`] provides secure defaults
//! - **HTTPS enforcement**: `secure(true)` cookies in production
//! - **XSS protection**: `http_only(true)` prevents script access
//! - **CSRF mitigation**: `SameSite::Strict` for sensitive operations
//!
//! ### JWT Security
//! - **Persistent keys**: Use stable signing keys in production (see [`codecs::jwt::JsonWebToken`] docs)
//! - **Proper expiration**: Set reasonable JWT expiration times
//! - **Key rotation**: Support for periodic key updates
//!
//! ### Timing Attack Protection
//! Built-in protection against timing attacks:
//! - Constant-time credential verification using the `subtle` crate
//! - Always performs password verification, even for non-existent users
//! - Unified error responses prevent user enumeration
//! - Applied to all storage backends
//!
//! ## Permission System
//! - **Compile-time validation**: Use [`validate_permissions!`] macro for collision detection
//! - **Runtime validation**: [`permissions::PermissionCollisionChecker`] for dynamic permissions
//! - **Deterministic hashing**: No coordination needed between distributed nodes
//! - **Efficient storage**: Bitmap-based permission storage with fast lookups

pub use axum_extra;
pub use cookie;
pub use jsonwebtoken;
#[cfg(feature = "prometheus")]
pub use prometheus;
pub use serde_json;
pub use uuid;

pub mod accounts;
#[cfg(feature = "audit-logging")]
pub mod audit;
pub mod authn;
pub mod authz;
pub mod codecs;
#[cfg(feature = "storage-seaorm")]
pub mod comma_separated_value;
pub mod cookie_template;
pub mod credentials;
pub mod gate;
pub mod groups;
pub mod hashing;
pub mod permissions;
pub mod repositories;
pub mod roles;
pub mod route_handlers;
pub mod secrets;
pub mod verification_result;

pub mod errors;

/// Common types and functions for quick imports.
pub mod prelude {
    pub use crate::accounts::Account;
    pub use crate::codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
    pub use crate::cookie_template::CookieTemplateBuilder;
    pub use crate::credentials::Credentials;
    pub use crate::gate::Gate;
    pub use crate::groups::Group;
    pub use crate::jsonwebtoken::{DecodingKey, EncodingKey};
    pub use crate::roles::Role;
}
