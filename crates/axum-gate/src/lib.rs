#![deny(missing_docs)]
#![doc = include_str!("../../../README.md")]

mod application;
mod domain;
pub mod errors;

mod infrastructure;
mod ports;

// Core domain entities that users work with directly
pub use domain::entities::{Account, Credentials, Group, Role};
pub use domain::values::{AccessScope, Secret, VerificationResult};

// Domain traits needed for custom implementations
pub use domain::traits::AccessHierarchy;

// Domain services that users interact with
pub use domain::services::access_policy::AccessPolicy;
pub use domain::services::authorization::AuthorizationService;
pub use domain::services::permissions::{
    PermissionChecker,
    PermissionId,
    const_sha256_u32, // Needed for validate_permissions! macro
    validate_permission_uniqueness,
};

// Permission validation utilities
pub use domain::services::permissions::validation::{
    ApplicationValidator, PermissionCollision as ValidationPermissionCollision,
    PermissionCollisionChecker, ValidationReport,
};

// Port definitions
pub use ports::Codec;
pub use ports::auth::{CredentialsVerifier, HashingService};
pub use ports::repositories::{AccountRepository, SecretRepository};

// Application services users need
pub use application::accounts::{AccountDeleteService, AccountInsertService};
pub use application::auth::{LoginResult, LoginService, LogoutService};

// Repository implementations
#[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
pub use infrastructure::storage::TableNames;
pub use infrastructure::storage::memory;
#[cfg(feature = "storage-seaorm")]
pub use infrastructure::storage::sea_orm;
#[cfg(feature = "storage-surrealdb")]
pub use infrastructure::storage::surrealdb;

// Web components - the main user-facing API
pub use infrastructure::web::{gate::Gate, route_handlers};

// JWT and authentication utilities
pub use infrastructure::jwt::{
    JsonWebToken, JsonWebTokenOptions, JwtClaims, JwtValidationResult, JwtValidationService,
    RegisteredClaims,
};

// Hashing utilities
pub use infrastructure::hashing::{Argon2Hasher, HashedValue};

// Re-export external dependencies users need
pub use cookie;
pub use jsonwebtoken;
