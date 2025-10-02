//! Unified error types exposed by this crate.
//!
//! This module contains error types you mostly need when using this crate:
//! - `Error`: root enum wrapping all layer-specific errors
//! - `Result<T>`: convenience alias
//! - `UserFriendlyError`: trait providing multiple message levels
//! - Layer enums: `DomainError`, `ApplicationError`, `InfrastructureError`, `PortError`
//!
//! # Error Message Levels
//! Each error provides three message levels for different audiences:
//! - **User Message**: Clear, actionable message for end users
//! - **Developer Message**: Technical details for debugging
//! - **Support Code**: Unique reference code for customer support
//!
//! # When to Use Each Variant
//! - `Domain` – Pure business rule / invariant violations (no external side effects)
//! - `Application` – Orchestration or use-case flow failures (combining domain + ports)
//! - `Infrastructure` – Failures talking to external systems (DB, JWT, network, etc.)
//! - `Port` – Adapter / interface contract violations (repositories, codecs, hashing)
//!
//! # Basic Example
//! ```rust
//! use axum_gate::errors::{Error, DomainError, Result, UserFriendlyError};
//!
//! fn do_domain_check(flag: bool) -> Result<()> {
//!     if !flag {
//!         let error = Error::Domain(
//!             DomainError::permission_collision(42, vec!["read:alpha".into(), "read:beta".into()])
//!         );
//!         println!("User sees: {}", error.user_message());
//!         println!("Developer sees: {}", error.developer_message());
//!         return Err(error);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//! ```rust
//! use axum_gate::errors::{Error, UserFriendlyError};
//!
//! fn handle_error(err: &Error) -> (String, String, String) {
//!     (
//!         err.user_message(),
//!         err.developer_message(),
//!         err.support_code()
//!     )
//! }
//! ```

use std::fmt;
use thiserror::Error;

// Re-export only the primary error enums and auth-specific leaf errors needed by users.
pub use crate::application::errors::{ApplicationError, AuthenticationError};
pub use crate::domain::errors::DomainError;
pub use crate::infrastructure::errors::InfrastructureError;
pub use crate::ports::errors::PortError;

/// Trait providing user-friendly error messaging at multiple levels.
///
/// This trait ensures all errors provide appropriate messages for different
/// audiences while maintaining security and consistency.
pub trait UserFriendlyError: fmt::Display + fmt::Debug {
    /// User-facing message that is clear, actionable, and non-technical.
    ///
    /// This message should:
    /// - Use plain language that any user can understand
    /// - Provide actionable guidance when possible
    /// - Never leak sensitive information
    /// - Be empathetic and helpful in tone
    ///
    /// # Examples
    /// - "We're experiencing technical difficulties. Please try again in a moment."
    /// - "Your session has expired. Please sign in again to continue."
    /// - "There's an issue with your account. Please contact our support team."
    fn user_message(&self) -> String;

    /// Technical message with detailed information for developers and logs.
    ///
    /// This message should:
    /// - Include precise technical details
    /// - Provide context for debugging
    /// - Include relevant identifiers and parameters
    /// - Be structured for parsing by monitoring tools
    fn developer_message(&self) -> String;

    /// Unique support reference code for customer service and troubleshooting.
    ///
    /// This code should:
    /// - Be unique and easily communicable
    /// - Allow support teams to identify the exact error
    /// - Not contain sensitive information
    /// - Be consistent across error instances
    fn support_code(&self) -> String;

    /// Error severity level for proper handling and alerting.
    fn severity(&self) -> ErrorSeverity;

    /// Suggested user actions for resolving the error.
    fn suggested_actions(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether this error should be retryable by the user.
    fn is_retryable(&self) -> bool {
        false
    }
}

/// Error severity levels for proper categorization and handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical system error requiring immediate attention
    Critical,
    /// Error that prevents normal operation
    Error,
    /// Warning that may indicate a problem
    Warning,
    /// Informational message about an expected condition
    Info,
}

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
///
/// Each error variant implements `UserFriendlyError` to provide appropriate
/// messaging for different audiences while maintaining security and consistency.
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

impl UserFriendlyError for Error {
    fn user_message(&self) -> String {
        match self {
            Error::Domain(err) => err.user_message(),
            Error::Application(err) => err.user_message(),
            Error::Infrastructure(err) => err.user_message(),
            Error::Port(err) => err.user_message(),
        }
    }

    fn developer_message(&self) -> String {
        match self {
            Error::Domain(err) => err.developer_message(),
            Error::Application(err) => err.developer_message(),
            Error::Infrastructure(err) => err.developer_message(),
            Error::Port(err) => err.developer_message(),
        }
    }

    fn support_code(&self) -> String {
        match self {
            Error::Domain(err) => format!("DOM-{}", err.support_code()),
            Error::Application(err) => format!("APP-{}", err.support_code()),
            Error::Infrastructure(err) => format!("INF-{}", err.support_code()),
            Error::Port(err) => format!("PORT-{}", err.support_code()),
        }
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            Error::Domain(err) => err.severity(),
            Error::Application(err) => err.severity(),
            Error::Infrastructure(err) => err.severity(),
            Error::Port(err) => err.severity(),
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            Error::Domain(err) => err.suggested_actions(),
            Error::Application(err) => err.suggested_actions(),
            Error::Infrastructure(err) => err.suggested_actions(),
            Error::Port(err) => err.suggested_actions(),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Error::Domain(err) => err.is_retryable(),
            Error::Application(err) => err.is_retryable(),
            Error::Infrastructure(err) => err.is_retryable(),
            Error::Port(err) => err.is_retryable(),
        }
    }
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
        let error = Error::Domain(DomainError::permission_collision(
            123u64,
            permissions.clone(),
        ));

        // Test error structure
        match &error {
            Error::Domain(DomainError::PermissionCollision {
                collision_count,
                hash_id,
                permissions: perms,
            }) => {
                assert_eq!(*collision_count, 2);
                assert_eq!(*hash_id, 123u64);
                assert_eq!(*perms, permissions);
            }
            _ => panic!("Expected PermissionCollision variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("technical issue"));
        assert!(error.developer_message().contains("Permission collision"));
        assert_eq!(error.support_code(), "DOM-PERM-COLLISION-123");
        assert_eq!(error.severity(), ErrorSeverity::Critical);
        assert!(!error.suggested_actions().is_empty());
    }

    #[test]
    fn application_error_authentication() {
        let auth_error = AuthenticationError::InvalidCredentials;
        let error = Error::Application(ApplicationError::authentication(
            auth_error,
            Some("test context".to_string()),
        ));

        // Test error structure
        match &error {
            Error::Application(ApplicationError::Authentication {
                auth_error,
                context,
            }) => {
                matches!(auth_error, AuthenticationError::InvalidCredentials);
                assert_eq!(*context, Some("test context".to_string()));
            }
            _ => panic!("Expected Authentication variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("username or password"));
        assert!(error.developer_message().contains("Invalid credentials"));
        assert_eq!(error.support_code(), "APP-AUTH-INVALID-CREDS");
        assert_eq!(error.severity(), ErrorSeverity::Warning);
        assert!(
            error
                .suggested_actions()
                .iter()
                .any(|action| action.contains("username") || action.contains("password"))
        );
    }

    #[test]
    fn infrastructure_error_database() {
        let error = Error::Infrastructure(InfrastructureError::database(
            DatabaseOperation::Query,
            "Connection failed",
        ));

        // Test error structure
        match &error {
            Error::Infrastructure(InfrastructureError::Database {
                operation, message, ..
            }) => {
                matches!(operation, DatabaseOperation::Query);
                assert_eq!(*message, "Connection failed");
            }
            _ => panic!("Expected Database variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("technical difficulties"));
        assert!(error.developer_message().contains("Database"));
        assert!(error.support_code().starts_with("INF-DB-QUERY-"));
        assert_eq!(error.severity(), ErrorSeverity::Error);
        assert!(error.is_retryable());
    }

    #[test]
    fn port_error_repository() {
        let error = Error::Port(PortError::repository(
            RepositoryType::Account,
            "Insert failed",
        ));

        // Test error structure
        match &error {
            Error::Port(PortError::Repository {
                repository,
                message,
                ..
            }) => {
                matches!(repository, RepositoryType::Account);
                assert_eq!(*message, "Insert failed");
            }
            _ => panic!("Expected Repository variant"),
        }

        // Test user-friendly messages
        assert!(error.user_message().contains("account information"));
        assert!(error.developer_message().contains("Repository"));
        assert!(error.support_code().starts_with("PORT-REPO-ACCOUNT-"));
        assert_eq!(error.severity(), ErrorSeverity::Critical);
        assert!(error.is_retryable());
    }

    #[test]
    fn error_display() {
        let error = Error::Domain(DomainError::permission_collision(
            123,
            vec!["test".to_string()],
        ));
        let display = format!("{}", error);
        assert!(display.contains("Permission collision"));

        // Test all message levels
        assert!(!error.user_message().is_empty());
        assert!(!error.developer_message().is_empty());
        assert!(!error.support_code().is_empty());
        assert!(!matches!(error.severity(), ErrorSeverity::Info));
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", AccountOperation::Create), "create");
        assert_eq!(format!("{}", DatabaseOperation::Query), "query");
        assert_eq!(format!("{}", JwtOperation::Encode), "encode");
        assert_eq!(format!("{}", CodecOperation::Decode), "decode");
        assert_eq!(format!("{}", HashingOperation::Verify), "verify");
    }

    #[test]
    fn error_severity_levels() {
        let domain_error = Error::Domain(DomainError::permission_collision(
            123,
            vec!["test".to_string()],
        ));
        assert_eq!(domain_error.severity(), ErrorSeverity::Critical);

        // Test that all severity levels work
        assert_ne!(ErrorSeverity::Critical, ErrorSeverity::Error);
        assert_ne!(ErrorSeverity::Error, ErrorSeverity::Warning);
        assert_ne!(ErrorSeverity::Warning, ErrorSeverity::Info);
    }

    #[test]
    fn error_support_codes_are_unique() {
        let domain_error = Error::Domain(DomainError::permission_collision(
            123,
            vec!["test".to_string()],
        ));
        let app_error = Error::Application(ApplicationError::authentication(
            AuthenticationError::InvalidCredentials,
            None,
        ));

        assert_ne!(domain_error.support_code(), app_error.support_code());
        assert!(domain_error.support_code().starts_with("DOM-"));
        assert!(app_error.support_code().starts_with("APP-"));
    }

    #[test]
    fn error_suggested_actions() {
        let error = Error::Application(ApplicationError::authentication(
            AuthenticationError::InvalidCredentials,
            None,
        ));
        let actions = error.suggested_actions();
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|action| action.contains("username")
            || action.contains("password")
            || action.contains("check")));
    }
}
