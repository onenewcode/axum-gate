//! Comprehensive error handling for the axum-gate hexagonal architecture.
//!
//! This module provides layer-specific error types that respect architectural boundaries:
//! - Domain layer: Pure business logic errors
//! - Application layer: Use case orchestration errors
//! - Infrastructure layer: External system integration errors
//! - Port layer: Interface contract violations
//!
//! # Examples
//!
//! ## Creating Domain Errors
//!
//! ```rust
//! use axum_gate::errors::{DomainError, Error, PermissionCollision};
//!
//! // Permission collision error
//! let collision = PermissionCollision {
//!     id: 12345,
//!     permissions: vec!["read:file".to_string(), "read:document".to_string()],
//! };
//! let domain_error = Error::Domain(DomainError::PermissionCollision {
//!     collision_count: 2,
//!     hash_id: 12345,
//!     permissions: vec!["read:file".to_string(), "read:document".to_string()],
//! });
//! ```
//!
//! ## Creating Application Errors
//!
//! ```rust
//! use axum_gate::errors::{ApplicationError, AccountOperation, AuthenticationError, Error};
//!
//! // Account service error
//! let service_error = Error::Application(ApplicationError::AccountService {
//!     operation: AccountOperation::Create,
//!     message: "Failed to create account".to_string(),
//!     account_id: Some("user123".to_string()),
//! });
//!
//! // Authentication error
//! let auth_error = Error::Application(ApplicationError::Authentication {
//!     auth_error: AuthenticationError::InvalidCredentials,
//!     context: Some("Login attempt from IP 192.168.1.1".to_string()),
//! });
//! ```
//!
//! ## Creating Infrastructure Errors
//!
//! ```rust
//! use axum_gate::errors::{InfrastructureError, DatabaseOperation, JwtOperation, Error};
//!
//! // Database error
//! let db_error = Error::Infrastructure(InfrastructureError::Database {
//!     operation: DatabaseOperation::Query,
//!     message: "Connection timeout".to_string(),
//!     table: Some("accounts".to_string()),
//!     record_id: Some("user123".to_string()),
//! });
//!
//! // JWT error
//! let jwt_error = Error::Infrastructure(InfrastructureError::Jwt {
//!     operation: JwtOperation::Decode,
//!     message: "Invalid signature".to_string(),
//!     token_preview: Some("eyJhbGciOiJIUzI1NiIs...".to_string()),
//! });
//! ```
//!
//! ## Creating Port Errors
//!
//! ```rust
//! use axum_gate::errors::{PortError, RepositoryType, HashingOperation, Error};
//!
//! // Repository error
//! let repo_error = Error::Port(PortError::Repository {
//!     repository: RepositoryType::Account,
//!     message: "Store operation failed".to_string(),
//!     operation: Some("insert".to_string()),
//! });
//!
//! // Hashing error
//! let hash_error = Error::Port(PortError::Hashing {
//!     operation: HashingOperation::Verify,
//!     message: "Password verification failed".to_string(),
//!     algorithm: Some("Argon2".to_string()),
//! });
//! ```
//!
//! ## Error Pattern Matching
//!
//! ```rust
//! use axum_gate::errors::{Error, DomainError, ApplicationError, InfrastructureError, PortError};
//!
//! fn handle_error(error: Error) {
//!     match error {
//!         Error::Domain(DomainError::PermissionCollision { collision_count, .. }) => {
//!             println!("Permission collision detected: {} conflicts", collision_count);
//!         },
//!         Error::Application(ApplicationError::Authentication { auth_error, .. }) => {
//!             println!("Authentication failed: {}", auth_error);
//!         },
//!         Error::Infrastructure(InfrastructureError::Database { operation, message, .. }) => {
//!             println!("Database {} failed: {}", operation, message);
//!         },
//!         Error::Port(PortError::Repository { repository, message, .. }) => {
//!             println!("Repository {} error: {}", repository, message);
//!         },
//!         _ => {
//!             println!("Other error: {}", error);
//!         },
//!     }
//! }
//! ```

use thiserror::Error;

// Re-export error types from individual modules
pub use crate::application::error::{AccountOperation, ApplicationError, AuthenticationError};
pub use crate::domain::error::{DomainError, PermissionCollision};
pub use crate::infrastructure::error::{DatabaseOperation, InfrastructureError, JwtOperation};
pub use crate::ports::error::{CodecOperation, HashingOperation, PortError, RepositoryType};

/// Result type alias using our comprehensive Error type.
///
/// This provides a convenient way to return results from functions that can fail
/// with any of the layer-specific errors defined in this module.
///
/// # Examples
///
/// ```rust
/// use axum_gate::errors::{Result, Error, DomainError};
///
/// fn validate_account(user_id: &str) -> Result<()> {
///     if user_id.is_empty() {
///         return Err(Error::Domain(DomainError::permission_collision(
///             12345,
///             vec!["invalid".to_string()]
///         )));
///     }
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// Root error type for the axum-gate library.
///
/// This enum represents all possible errors that can occur across different
/// architectural layers, providing a unified error handling interface while
/// maintaining clear separation of concerns.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Domain layer business logic errors
    #[error(transparent)]
    Domain(#[from] DomainError),

    /// Application layer service orchestration errors
    #[error(transparent)]
    Application(#[from] ApplicationError),

    /// Infrastructure layer external system errors
    #[error(transparent)]
    Infrastructure(#[from] InfrastructureError),

    /// Port layer interface contract violations
    #[error(transparent)]
    Port(#[from] PortError),
}

// External library error conversions
#[cfg(feature = "storage-surrealdb")]
impl From<surrealdb::Error> for Error {
    fn from(err: surrealdb::Error) -> Self {
        Error::Infrastructure(InfrastructureError::Database {
            operation: DatabaseOperation::Query,
            message: format!("SurrealDB error: {}", err),
            table: None,
            record_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_error_permission_collision() {
        let permissions = vec!["read:file".to_string(), "write:file".to_string()];
        let error = DomainError::permission_collision(123, permissions.clone());

        match error {
            DomainError::PermissionCollision {
                collision_count,
                hash_id,
                permissions: perms,
            } => {
                assert_eq!(collision_count, 2);
                assert_eq!(hash_id, 123);
                assert_eq!(perms, permissions);
            }
        }
    }

    #[test]
    fn application_error_authentication() {
        let auth_error = AuthenticationError::InvalidCredentials;
        let error = ApplicationError::authentication(auth_error, Some("test context".to_string()));

        match error {
            ApplicationError::Authentication {
                auth_error,
                context,
            } => {
                matches!(auth_error, AuthenticationError::InvalidCredentials);
                assert_eq!(context, Some("test context".to_string()));
            }
            ApplicationError::AccountService { .. } => panic!("Expected Authentication variant"),
        }
    }

    #[test]
    fn infrastructure_error_database() {
        let error = InfrastructureError::database(DatabaseOperation::Query, "Connection failed");

        match error {
            InfrastructureError::Database {
                operation, message, ..
            } => {
                matches!(operation, DatabaseOperation::Query);
                assert_eq!(message, "Connection failed");
            }
            InfrastructureError::Jwt { .. } => panic!("Expected Database variant"),
        }
    }

    #[test]
    fn port_error_repository() {
        let error = PortError::repository(RepositoryType::Account, "Insert failed");

        match error {
            PortError::Repository {
                repository,
                message,
                ..
            } => {
                matches!(repository, RepositoryType::Account);
                assert_eq!(message, "Insert failed");
            }
            PortError::Codec { .. } | PortError::Hashing { .. } => {
                panic!("Expected Repository variant")
            }
        }
    }

    #[test]
    fn error_display() {
        let error = Error::Domain(DomainError::permission_collision(
            123,
            vec!["test".to_string()],
        ));
        let display = format!("{}", error);
        assert!(display.contains("Permission collision"));
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", AccountOperation::Create), "create");
        assert_eq!(format!("{}", DatabaseOperation::Query), "query");
        assert_eq!(format!("{}", JwtOperation::Encode), "encode");
        assert_eq!(format!("{}", CodecOperation::Decode), "decode");
        assert_eq!(format!("{}", HashingOperation::Verify), "verify");
    }
}
