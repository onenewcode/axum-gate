//! Infrastructure layer error types for external system integration failures.
//!
//! This module contains error types that represent failures in external systems,
//! databases, web servers, and other infrastructure components.

use std::fmt;
use thiserror::Error;

/// Infrastructure layer errors for external system integration failures.
///
/// These errors represent failures in external systems, databases, web servers,
/// and other infrastructure components.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InfrastructureError {
    /// Database operation error
    #[error("Database error: {operation} failed - {message}")]
    Database {
        /// The database operation that failed
        operation: DatabaseOperation,
        /// Description of the failure
        message: String,
        /// The table or collection involved
        table: Option<String>,
        /// The record ID if applicable
        record_id: Option<String>,
    },

    /// JWT token processing error
    #[error("JWT error: {operation} - {message}")]
    Jwt {
        /// The JWT operation that failed
        operation: JwtOperation,
        /// Description of the failure
        message: String,
        /// The token that caused the error (truncated for security)
        token_preview: Option<String>,
    },
}

/// Database operation types
#[derive(Debug, Clone)]
pub enum DatabaseOperation {
    /// Database connection operation
    Connect,
    /// Database query operation
    Query,
    /// Database insert operation
    Insert,
    /// Database update operation
    Update,
    /// Database delete operation
    Delete,
}

impl fmt::Display for DatabaseOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseOperation::Connect => write!(f, "connect"),
            DatabaseOperation::Query => write!(f, "query"),
            DatabaseOperation::Insert => write!(f, "insert"),
            DatabaseOperation::Update => write!(f, "update"),
            DatabaseOperation::Delete => write!(f, "delete"),
        }
    }
}

/// JWT operation types
#[derive(Debug, Clone)]
pub enum JwtOperation {
    /// JWT encode operation
    Encode,
    /// JWT decode operation
    Decode,
    /// JWT validation operation
    Validate,
}

impl fmt::Display for JwtOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtOperation::Encode => write!(f, "encode"),
            JwtOperation::Decode => write!(f, "decode"),
            JwtOperation::Validate => write!(f, "validate"),
        }
    }
}

impl InfrastructureError {
    /// Create a database error
    pub fn database(operation: DatabaseOperation, message: impl Into<String>) -> Self {
        InfrastructureError::Database {
            operation,
            message: message.into(),
            table: None,
            record_id: None,
        }
    }

    /// Create a database error with table context
    pub fn database_with_context(
        operation: DatabaseOperation,
        message: impl Into<String>,
        table: Option<String>,
        record_id: Option<String>,
    ) -> Self {
        InfrastructureError::Database {
            operation,
            message: message.into(),
            table,
            record_id,
        }
    }

    /// Create a JWT error
    pub fn jwt(operation: JwtOperation, message: impl Into<String>) -> Self {
        InfrastructureError::Jwt {
            operation,
            message: message.into(),
            token_preview: None,
        }
    }

    /// Create a JWT error with token preview
    pub fn jwt_with_preview(
        operation: JwtOperation,
        message: impl Into<String>,
        token_preview: Option<String>,
    ) -> Self {
        InfrastructureError::Jwt {
            operation,
            message: message.into(),
            token_preview,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_error_constructor() {
        let error = InfrastructureError::database(DatabaseOperation::Query, "Connection failed");

        match error {
            InfrastructureError::Database {
                operation, message, ..
            } => {
                matches!(operation, DatabaseOperation::Query);
                assert_eq!(message, "Connection failed");
            }
            _ => panic!("Expected Database variant"),
        }
    }

    #[test]
    fn jwt_error_constructor() {
        let error = InfrastructureError::jwt(JwtOperation::Decode, "Invalid token");

        match error {
            InfrastructureError::Jwt {
                operation, message, ..
            } => {
                matches!(operation, JwtOperation::Decode);
                assert_eq!(message, "Invalid token");
            }
            _ => panic!("Expected Jwt variant"),
        }
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", DatabaseOperation::Query), "query");
        assert_eq!(format!("{}", JwtOperation::Encode), "encode");
    }

    #[test]
    fn error_display() {
        let error = InfrastructureError::database(DatabaseOperation::Insert, "Insert failed");
        let display = format!("{}", error);
        assert!(display.contains("Database error"));
        assert!(display.contains("insert failed"));
        assert!(display.contains("Insert failed"));
    }

    #[test]
    fn database_with_context() {
        let error = InfrastructureError::database_with_context(
            DatabaseOperation::Update,
            "Update failed",
            Some("users".to_string()),
            Some("user123".to_string()),
        );

        match error {
            InfrastructureError::Database {
                operation,
                message,
                table,
                record_id,
            } => {
                matches!(operation, DatabaseOperation::Update);
                assert_eq!(message, "Update failed");
                assert_eq!(table, Some("users".to_string()));
                assert_eq!(record_id, Some("user123".to_string()));
            }
            _ => panic!("Expected Database variant"),
        }
    }
}
