//! Unified error types exposed by this crate.
//!
//! This module contains error types you mostly need when using this crate:
//! - `Error`: root enum wrapping all layer-specific errors
//! - `Result<T>`: convenience alias
//! - Layer enums: `DomainError`, `ApplicationError`, `InfrastructureError`, `PortError`
//!
//! # When to Use Each Variant
//! - `Domain` – Pure business rule / invariant violations (no external side effects)
//! - `Application` – Orchestration or use-case flow failures (combining domain + ports)
//! - `Infrastructure` – Failures talking to external systems (DB, JWT, network, etc.)
//! - `Port` – Adapter / interface contract violations (repositories, codecs, hashing)
//!
//! # Basic Example
//! ```rust
//! use axum_gate::errors::{Error, DomainError, Result};
//!
//! fn do_domain_check(flag: bool) -> Result<()> {
//!     if !flag {
//!         return Err(Error::Domain(
//!             DomainError::permission_collision(42, vec!["read:alpha".into(), "read:beta".into()])
//!         ));
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Matching
//! ```rust
//! use axum_gate::errors::{Error, DomainError, ApplicationError};
//!
//! fn classify(err: &Error) -> &'static str {
//!     match err {
//!         Error::Domain(DomainError::PermissionCollision { .. }) => "domain/collision",
//!         Error::Domain(_) => "domain",
//!         Error::Application(ApplicationError::Authentication { .. }) => "auth",
//!         Error::Application(_) => "application",
//!         Error::Infrastructure(_) => "infrastructure",
//!         Error::Port(_) => "port",
//!     }
//! }
//! ```

use thiserror::Error;

// Re-export only the primary error enums and auth-specific leaf errors needed by users.
pub use crate::application::errors::{ApplicationError, AuthenticationError};
pub use crate::domain::errors::DomainError;
pub use crate::infrastructure::errors::InfrastructureError;
pub use crate::ports::errors::PortError;

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
            operation: crate::infrastructure::errors::DatabaseOperation::Query,
            message: format!("SurrealDB error: {}", err),
            table: None,
            record_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Import operation enums from their defining modules now that they are no longer re-exported.
    use crate::application::errors::AccountOperation;
    use crate::infrastructure::errors::{DatabaseOperation, JwtOperation};
    use crate::ports::errors::{CodecOperation, HashingOperation, RepositoryType};

    #[test]
    fn domain_error_permission_collision() {
        let permissions = vec!["read:file".to_string(), "write:file".to_string()];
        let error = DomainError::permission_collision(123u64, permissions.clone());

        match error {
            DomainError::PermissionCollision {
                collision_count,
                hash_id,
                permissions: perms,
            } => {
                assert_eq!(collision_count, 2);
                assert_eq!(hash_id, 123u64);
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
