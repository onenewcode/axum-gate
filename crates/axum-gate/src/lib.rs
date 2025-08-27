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
//! use axum_gate::{Gate, AccessPolicy, auth, storage, jwt};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create JWT codec with sensible defaults
//!     let jwt_codec = Arc::new(jwt::JsonWebToken::default());
//!
//!     // Admin-only protection
//!     let app = Router::new()
//!         .route("/admin", get(admin_handler))
//!         .layer(
//!             Gate::cookie_deny_all("my-app", jwt_codec)
//!                 .with_policy(AccessPolicy::require_role(auth::Role::Admin))
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

// Core authentication middleware - the main entry point
pub use infrastructure::web::gate::{CookieGate, Gate};

// Essential authentication types
pub mod auth {
    //! Core authentication types and utilities.
    //!
    //! This module contains the fundamental building blocks for authentication:
    //! - User accounts and credentials
    //! - Roles and groups
    //! - Access policies
    //! - Account management services

    pub use crate::domain::entities::{Account, Credentials, Group, Role};
    pub use crate::domain::services::access_policy::AccessPolicy;
    pub use crate::domain::values::{PermissionId, Permissions};

    // Account management
    pub use crate::application::accounts::{AccountDeleteService, AccountInsertService};

    // Ready-to-use handlers for login/logout
    pub use crate::infrastructure::web::route_handlers::{login, logout};

    // Permission validation utilities
    pub use crate::domain::services::permissions::validate_permission_uniqueness;
}

// JWT handling made simple
pub mod jwt {
    //! JWT token handling and configuration.
    //!
    //! Everything you need to work with JWT tokens:
    //! - Token creation and validation
    //! - Claims management
    //! - Encoding/decoding utilities

    pub use crate::infrastructure::jwt::{JsonWebToken, JwtClaims, RegisteredClaims};

    // Advanced JWT configuration for power users
    pub mod advanced {
        //! Advanced JWT configuration and validation utilities.
        pub use crate::infrastructure::jwt::{
            JsonWebTokenOptions, JwtValidationResult, JwtValidationService,
        };
    }
}

// HTTP utilities
pub mod http {
    //! HTTP-related utilities for web integration.
    //!
    //! Contains cookie handling, request/response utilities,
    //! and other HTTP-specific functionality.

    pub use axum_extra::extract::cookie::CookieJar;
    pub use cookie::{self, SameSite};

    // Re-export commonly used cookie duration type
    pub use cookie::time::Duration;
}

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
    pub use crate::infrastructure::repositories::surrealdb::{DatabaseScope, SurrealDbRepository};

    #[cfg(feature = "storage-seaorm")]
    pub use crate::infrastructure::repositories::sea_orm::{SeaOrmRepository, models};

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

    // Low-level values and utilities
    pub use crate::domain::values::{
        AccessScope, AsPermissionName, Secret, VerificationResult, const_sha256_u32,
    };
}

// Essential utilities that most users will need
pub mod utils {
    //! Common utilities and helper functions.
    //!
    //! Contains frequently used types and functions that don't
    //! fit into specific modules but are commonly needed.

    pub use uuid::Uuid;

    // Commonly used external crates that users often need
    pub mod external {
        //! Re-exports of commonly used external crate functionality.
        //!
        //! These are provided for convenience but you can also import
        //! these crates directly to avoid potential version conflicts.

        pub use jsonwebtoken;
        pub use serde_json;
    }
}

// Convenience re-exports for the most common use case
pub use auth::{AccessPolicy, Account, Credentials, Group, Role};
