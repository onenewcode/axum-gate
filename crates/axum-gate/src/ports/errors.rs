//! Ports layer error types for interface contract violations.
//!
//! This module contains error types that represent failures in port interfaces
//! and contract violations between the application layer and external adapters.

use std::fmt;

use thiserror::Error;

/// Port layer errors for interface contract violations.
///
/// These errors occur when adapters fail to properly implement port interfaces
/// or when there are contract violations between layers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PortError {
    /// Repository contract violation
    #[error("Repository error: {repository} - {message}")]
    Repository {
        /// The type of repository
        repository: RepositoryType,
        /// Description of the repository error
        message: String,
        /// The operation that failed
        operation: Option<String>,
    },

    /// Codec contract violation
    #[error("Codec error: {operation} - {message}")]
    Codec {
        /// The codec operation that failed
        operation: CodecOperation,
        /// Description of the codec error
        message: String,
        /// The payload type being processed
        payload_type: Option<String>,
    },

    /// Hashing service contract violation
    #[error("Hashing error: {operation} - {message}")]
    Hashing {
        /// The hashing operation that failed
        operation: HashingOperation,
        /// Description of the hashing error
        message: String,
        /// The hashing algorithm used
        algorithm: Option<String>,
    },
}

/// Repository type identifiers
#[derive(Debug, Clone)]
pub enum RepositoryType {
    /// Account repository
    Account,
    /// Secret repository
    Secret,
}

impl fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryType::Account => write!(f, "account"),
            RepositoryType::Secret => write!(f, "secret"),
        }
    }
}

/// Codec operation types
#[derive(Debug, Clone)]
pub enum CodecOperation {
    /// Encode operation
    Encode,
    /// Decode operation
    Decode,
}

impl fmt::Display for CodecOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecOperation::Encode => write!(f, "encode"),
            CodecOperation::Decode => write!(f, "decode"),
        }
    }
}

/// Hashing operation types
#[derive(Debug, Clone)]
pub enum HashingOperation {
    /// Hash operation
    Hash,
    /// Verify operation
    Verify,
}

impl fmt::Display for HashingOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashingOperation::Hash => write!(f, "hash"),
            HashingOperation::Verify => write!(f, "verify"),
        }
    }
}

impl PortError {
    /// Create a repository error
    pub fn repository(repository: RepositoryType, message: impl Into<String>) -> Self {
        PortError::Repository {
            repository,
            message: message.into(),
            operation: None,
        }
    }

    /// Create a repository error with operation context
    pub fn repository_with_operation(
        repository: RepositoryType,
        message: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        PortError::Repository {
            repository,
            message: message.into(),
            operation: Some(operation.into()),
        }
    }

    /// Create a codec error
    pub fn codec(operation: CodecOperation, message: impl Into<String>) -> Self {
        PortError::Codec {
            operation,
            message: message.into(),
            payload_type: None,
        }
    }

    /// Create a hashing error with algorithm context
    pub fn hashing_with_algorithm(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        PortError::Hashing {
            operation,
            message: message.into(),
            algorithm: Some(algorithm.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_error_constructor() {
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
            _ => panic!("Expected Repository variant"),
        }
    }

    #[test]
    fn codec_error_constructor() {
        let error = PortError::codec(CodecOperation::Encode, "Encoding failed");

        match error {
            PortError::Codec {
                operation, message, ..
            } => {
                matches!(operation, CodecOperation::Encode);
                assert_eq!(message, "Encoding failed");
            }
            _ => panic!("Expected Codec variant"),
        }
    }

    #[test]
    fn hashing_error_with_algorithm() {
        let error =
            PortError::hashing_with_algorithm(HashingOperation::Hash, "Hash failed", "Argon2");

        match error {
            PortError::Hashing {
                operation,
                message,
                algorithm,
            } => {
                matches!(operation, HashingOperation::Hash);
                assert_eq!(message, "Hash failed");
                assert_eq!(algorithm, Some("Argon2".to_string()));
            }
            _ => panic!("Expected Hashing variant"),
        }
    }

    #[test]
    fn operation_display() {
        assert_eq!(format!("{}", RepositoryType::Account), "account");
        assert_eq!(format!("{}", CodecOperation::Decode), "decode");
        assert_eq!(format!("{}", HashingOperation::Verify), "verify");
    }

    #[test]
    fn error_display() {
        let error = PortError::repository(RepositoryType::Secret, "Store operation failed");
        let display = format!("{}", error);
        assert!(display.contains("Repository error"));
        assert!(display.contains("secret"));
        assert!(display.contains("Store operation failed"));
    }

    #[test]
    fn repository_with_operation() {
        let error = PortError::repository_with_operation(
            RepositoryType::Account,
            "Query failed",
            "find_by_id",
        );

        match error {
            PortError::Repository {
                repository,
                message,
                operation,
            } => {
                matches!(repository, RepositoryType::Account);
                assert_eq!(message, "Query failed");
                assert_eq!(operation, Some("find_by_id".to_string()));
            }
            _ => panic!("Expected Repository variant"),
        }
    }
}
