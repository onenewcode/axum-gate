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
//!     // Create JWT codec
//!     let jwt_codec = Arc::new(jwt::JsonWebToken::<jwt::JwtClaims<Account<Role, Group>>>::default());
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
//!
//! async fn profile_handler(Extension(user): Extension<Account<Role, Group>>) -> String {
//!     format!("Hello {}, roles: {:?}", user.user_id, user.roles)
//! }
//! ```
//!
//! ## Security Best Practices
//!
//! - Use HTTPS with `secure(true)` cookies in production
//! - Enable `http_only(true)` to prevent XSS attacks
//! - Set appropriate JWT expiration times
//! - Validate permissions at application startup
//! - Use strong, random JWT signing keys
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
    /// Authentication middleware and builders.
    pub use crate::infrastructure::web::gate::{CookieGate, Gate};
}

// Essential authentication types
pub mod auth {
    //! Authentication types, policies, and account management.

    pub use crate::domain::entities::{Account, Credentials, Group, Role};
    pub use crate::domain::services::access_policy::AccessPolicy;
    pub use crate::domain::values::{PermissionId, Permissions};

    /// Account creation and management.
    pub use crate::application::accounts::{AccountDeleteService, AccountInsertService};

    /// Login and logout route handlers.
    pub use crate::infrastructure::web::route_handlers::{login, logout};

    /// Permission validation utilities.
    pub use crate::domain::services::permissions::validate_permission_uniqueness;
}

/// JWT token handling.
pub mod jwt {
    //! JWT creation, validation, and claims management.

    pub use crate::infrastructure::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};

    /// Advanced JWT configuration.
    pub mod advanced {
        //! Low-level JWT options and validation.
        pub use crate::infrastructure::jwt::{
            JsonWebTokenOptions, JwtValidationResult, JwtValidationService,
        };
    }
}

/// HTTP utilities.
pub mod http {
    //! Cookie handling and HTTP types.

    pub use axum_extra::extract::cookie::CookieJar;
    pub use cookie::{self, SameSite};

    /// Cookie duration type.
    pub use cookie::time::Duration;
}

/// Storage implementations.
pub mod storage {
    //! Account and secret storage backends.
    //!
    //! - `memory` - In-memory storage for development
    //! - `surrealdb` - SurrealDB backend (requires feature)
    //! - `seaorm` - SeaORM backend (requires feature)

    pub use crate::infrastructure::repositories::memory::{
        MemoryAccountRepository, MemorySecretRepository,
    };

    #[cfg(feature = "storage-surrealdb")]
    /// SurrealDB storage backend.
    pub mod surrealdb {
        pub use crate::infrastructure::repositories::surrealdb::{
            DatabaseScope, SurrealDbRepository,
        };
    }

    #[cfg(feature = "storage-seaorm")]
    /// SeaORM storage backend.
    pub mod seaorm {
        pub use crate::infrastructure::repositories::sea_orm::{SeaOrmRepository, models};
    }

    #[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
    pub use crate::infrastructure::repositories::TableNames;
}

/// Advanced APIs for custom implementations.
pub mod advanced {
    //! Low-level traits, services, and utilities for power users.

    /// Traits for custom storage and authentication.
    pub use crate::domain::traits::{AccessHierarchy, AsPermissionName};
    pub use crate::ports::Codec;
    pub use crate::ports::auth::{CredentialsVerifier, HashingService};
    pub use crate::ports::repositories::{AccountRepository, SecretRepository};

    /// Authentication and authorization services.
    pub use crate::application::auth::{LoginResult, LoginService, LogoutService};
    pub use crate::domain::services::authorization::AuthorizationService;
    pub use crate::domain::services::permissions::validation::{
        ApplicationValidator, PermissionCollisionChecker, ValidationReport,
    };

    /// Hashing and cryptographic utilities.
    pub use crate::infrastructure::hashing::{Argon2Hasher, HashedValue};

    /// Domain values and utility functions.
    pub use crate::domain::values::{AccessScope, Secret, VerificationResult, const_sha256_u64};
}

/// Common utilities.
pub mod utils {
    //! Helper types and external crate re-exports.

    pub use uuid::Uuid;

    /// External crate re-exports.
    pub mod external {
        //! Convenient access to commonly used external types.

        pub use jsonwebtoken;
        pub use serde_json;
    }
}
