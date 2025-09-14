//! Advanced / power‑user APIs.
//!
//! This module exposes lower-level building blocks for developers who need to:
//! - Implement custom repositories or hashing backends
//! - Integrate with non-standard JWT or transport layers
//! - Build custom login handlers instead of the provided route handlers
//! - Perform runtime permission validation (dynamic permission sources)
//! - Implement custom middleware instead of (or in addition to) the built-in `Gate`
//!
//! # Categories
//!
//! ## 1. Role & Permission Modeling
//! - [`AccessHierarchy`]: Implement on your role enum to enable supervisor traversal
//! - [`AsPermissionName`]: Implement on enums / structured permission types to map to canonical strings
//!
//! ## 2. Storage & Hashing Abstractions
//! - [`AccountRepository`], [`SecretRepository`]
//! - [`CredentialsVerifier`], [`HashingService`]
//! - [`Argon2Hasher`], [`HashedValue`]
//!
//! ## 3. Authentication Workflow
//! - [`LoginService`], [`LoginResult`]
//! - [`Secret`], [`VerificationResult`]
//!
//! ## 4. Permission Validation
//! - [`ApplicationValidator`]: Builder-style startup validation
//! - [`PermissionCollisionChecker`]: Detailed runtime collision/duplicate analysis
//! - [`ValidationReport`]
//!
//! ## 5. JWT Integration
//! - [`JwtValidationService`], [`JwtValidationResult`] for custom middleware
//! - [`Codec`] for alternative token encodings
//!
//! ## 6. When NOT to Use This
//! If you only:
//! - Protect routes with roles/groups/permissions
//! - Use built-in login/logout handlers
//! - Use provided backends
//!
//! Then you likely just need `prelude`, `auth`, `jwt`, `storage`, and `http`.
//!
//! # Example: Custom Login Endpoint
//! ```rust
//! use std::sync::Arc;
//! use axum_gate::advanced::{LoginService, CredentialsVerifier, AccountRepository, Codec, LoginResult};
//! use axum_gate::auth::{Credentials, Account, Role, Group};
//! use axum_gate::jwt::{RegisteredClaims, JwtClaims, JsonWebToken};
//!
//! async fn custom_login<Creds, AccRepo, C>(
//!     creds: Credentials<String>,
//!     creds_repo: Arc<Creds>,
//!     account_repo: Arc<AccRepo>,
//!     codec: Arc<C>
//! ) -> Result<String, String>
//! where
//!     Creds: CredentialsVerifier<uuid::Uuid>,
//!     AccRepo: AccountRepository<Role, Group>,
//!     C: Codec<Payload = JwtClaims<Account<Role, Group>>>,
//! {
//!     let registered = RegisteredClaims::new("my-app", chrono::Utc::now().timestamp() as u64 + 3600);
//!     let service = LoginService::<Role, Group>::new();
//!     match service.authenticate(creds, registered, creds_repo, account_repo, codec).await {
//!         LoginResult::Success(token) => Ok(token),
//!         LoginResult::InvalidCredentials { .. } => Err("invalid credentials".into()),
//!         LoginResult::InternalError { user_message, technical_message: _, support_code: _, retryable: _ } => Err(format!("internal error: {user_message}"))
//!     }
//! }
//! ```

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
