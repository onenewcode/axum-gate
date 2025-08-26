#![deny(missing_docs)]
#![doc = include_str!("../../../README.md")]

//! # axum-gate
//!
//! The most developer-friendly JWT cookie authentication for axum.
//!
//! ## Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create JWT codec
//!     let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!
//!     // Admin-only protection with sensible defaults
//!     let app = Router::new()
//!         .route("/admin", get(admin_handler))
//!         .layer(
//!             Gate::cookie_deny_all("my-app", jwt_codec)
//!                 .with_policy(AccessPolicy::require_role(Role::Admin))
//!         );
//! }
//!
//! async fn admin_handler() -> &'static str { "Hello admin!" }
//! ```

mod application;
mod domain;
pub mod errors;
mod infrastructure;
mod ports;

// Main API - This is what 99% of users should use
pub use infrastructure::web::gate::{CookieGate, Gate};
pub use infrastructure::web::route_handlers::{login, logout};

// Essential types every user needs
pub use domain::entities::{Account, Credentials, Group, Role};
pub use domain::services::access_policy::AccessPolicy;
pub use domain::values::{PermissionId, Permissions};

// JWT and cookie essentials
pub use axum_extra::extract::cookie::CookieJar;
pub use cookie::{self, SameSite, time::Duration};
pub use infrastructure::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};

// Account management made simple
pub use application::accounts::{AccountDeleteService, AccountInsertService};

// Permission validation
pub use domain::services::permissions::validate_permission_uniqueness;

// Storage implementations - organized by use case
pub mod storage {
    //! Ready-to-use storage implementations.
    //!
    //! Choose what fits your setup:
    //! - `memory` - Perfect for development and testing
    //! - `surrealdb` - For SurrealDB (enable `storage-surrealdb` feature)
    //! - `sea_orm` - For SeaORM (enable `storage-seaorm` feature)

    pub use crate::infrastructure::repositories::memory::{
        MemoryAccountRepository, MemorySecretRepository,
    };

    #[cfg(feature = "storage-surrealdb")]
    pub use crate::infrastructure::repositories::surrealdb::SurrealDbRepository;

    #[cfg(feature = "storage-seaorm")]
    pub use crate::infrastructure::repositories::sea_orm::SeaOrmRepository;

    #[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
    pub use crate::infrastructure::repositories::TableNames;
}

// Advanced customization for power users
pub mod advanced {
    //! Advanced APIs for power users who need fine-grained control.
    //!
    //! Most developers won't need this module. The main API handles
    //! common cases with sensible defaults.

    // Core traits for custom implementations
    pub use crate::domain::traits::AccessHierarchy;
    pub use crate::ports::Codec;
    pub use crate::ports::auth::{CredentialsVerifier, HashingService};
    pub use crate::ports::repositories::{AccountRepository, SecretRepository};

    // Low-level services
    pub use crate::application::auth::{LoginResult, LoginService, LogoutService};
    pub use crate::domain::services::authorization::AuthorizationService;
    pub use crate::domain::services::permissions::validation::{
        ApplicationValidator, PermissionCollisionChecker, ValidationReport,
    };

    // Infrastructure details
    pub use crate::infrastructure::hashing::{Argon2Hasher, HashedValue};
    pub use crate::infrastructure::jwt::{
        JsonWebTokenOptions, JwtValidationResult, JwtValidationService,
    };

    // Low-level values and utilities
    pub use crate::domain::values::{
        AccessScope, AsPermissionName, Secret, VerificationResult, const_sha256_u32,
    };
}

// Commonly needed external types
pub use jsonwebtoken;
pub use serde_json;
pub use uuid::Uuid;
