//! Application layer error types for service orchestration failures.
//!
//! This module contains error types that represent failures in application
//! services, use case orchestration, and business workflow coordination.

use std::fmt;

use thiserror::Error;

/// Application layer errors for service orchestration and use case failures.
///
/// These errors occur during the orchestration of domain objects and external
/// system interactions in application services.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApplicationError {
    /// Account management service error
    #[error("Account service error: {operation} failed - {message}")]
    AccountService {
        /// The operation that failed
        operation: AccountOperation,
        /// Description of the failure
        message: String,
        /// The account ID involved in the failed operation
        account_id: Option<String>,
    },

    /// Authentication service error
    #[error("Authentication error: {auth_error}")]
    Authentication {
        /// The specific authentication error
        #[source]
        auth_error: AuthenticationError,
        /// Additional context about the authentication attempt
        context: Option<String>,
    },
}

/// Specific authentication error types
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// Invalid credentials provided
    #[error("Invalid credentials provided")]
    InvalidCredentials,
}

/// Account operation types
#[derive(Debug, Clone)]
pub enum AccountOperation {
    /// Create account operation
    Create,
    /// Update account operation
    Update,
    /// Delete account operation
    Delete,
}

impl fmt::Display for AccountOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountOperation::Create => write!(f, "create"),
            AccountOperation::Update => write!(f, "update"),
            AccountOperation::Delete => write!(f, "delete"),
        }
    }
}

impl ApplicationError {
    /// Create an authentication error
    pub fn authentication(auth_error: AuthenticationError, context: Option<String>) -> Self {
        ApplicationError::Authentication {
            auth_error,
            context,
        }
    }

    /// Create an account service error
    pub fn account_service(
        operation: AccountOperation,
        message: impl Into<String>,
        account_id: Option<String>,
    ) -> Self {
        ApplicationError::AccountService {
            operation,
            message: message.into(),
            account_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_error_constructor() {
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
            _ => panic!("Expected Authentication variant"),
        }
    }

    #[test]
    fn account_service_error_constructor() {
        let error = ApplicationError::account_service(
            AccountOperation::Create,
            "Failed to create account",
            Some("user123".to_string()),
        );

        match error {
            ApplicationError::AccountService {
                operation,
                message,
                account_id,
            } => {
                matches!(operation, AccountOperation::Create);
                assert_eq!(message, "Failed to create account");
                assert_eq!(account_id, Some("user123".to_string()));
            }
            _ => panic!("Expected AccountService variant"),
        }
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", AccountOperation::Create), "create");
        assert_eq!(format!("{}", AccountOperation::Update), "update");
        assert_eq!(format!("{}", AccountOperation::Delete), "delete");
    }

    #[test]
    fn error_display() {
        let error = ApplicationError::account_service(AccountOperation::Create, "Test error", None);
        let display = format!("{}", error);
        assert!(display.contains("Account service error"));
        assert!(display.contains("create failed"));
        assert!(display.contains("Test error"));
    }
}
