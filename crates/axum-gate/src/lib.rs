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

/// Common types and functions for quick imports.
pub mod prelude {
    pub use crate::auth::{AccessPolicy, Account, Credentials, Group, Role};
    /// Authentication middleware.
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
    pub use crate::domain::traits::AccessHierarchy;
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
    pub use crate::domain::values::{
        AccessScope, AsPermissionName, Secret, VerificationResult, const_sha256_u32,
    };
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
