//! Secret-category native errors.
//!
//! Category-native error type for secret storage and hashing concerns,
//! aligning with the crate's categorical, domain-driven structure and
//! decoupled from layered/hexagonal naming.
//!
// //! Overview
//! - `SecretError`: category-native error enum for repository and hashing flows
//! - Uses `RepositoryOperation` and `RepositoryType::Secret` for repo context
//! - Uses `HashingOperation` for hashing context
//!
//! # Examples
//!
//! Repository operation failure:
//! ```rust
//! use axum_gate::errors::secrets::SecretError;
//! use axum_gate::errors::repositories::RepositoryOperation;
//!
//! let err = SecretError::repo_op(
//!     RepositoryOperation::Insert,
//!     "failed to persist secret",
//!     Some("user-123".into()),
//!     Some("insert_secret".into()),
//! );
//! ```
//!
//! Hashing failure with algorithm context:
//! ```rust
//! use axum_gate::errors::secrets::SecretError;
//! use axum_gate::errors::hashing::HashingOperation;
//!
//! let err = SecretError::hashing_with_algorithm(
//!     HashingOperation::Verify,
//!     "password verification failed",
//!     "argon2id",
//! );
//! ```

use crate::errors::hashing::HashingOperation;
use crate::errors::repositories::{RepositoryOperation, RepositoryType};
use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Secret-category native errors.
///
/// Use for secret repository and hashing/verification flows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    /// Secret repository operation failure.
    #[error("Secret repository error: {operation} - {message}")]
    Repository {
        /// The repository operation that failed.
        operation: RepositoryOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// Logical key/identifier (sanitized), e.g., user id.
        key: Option<String>,
        /// Additional context (non-sensitive), e.g., function/edge case.
        context: Option<String>,
    },

    /// Secret not found in repository.
    #[error("Secret not found")]
    NotFound {
        /// Logical key/identifier (sanitized).
        key: Option<String>,
    },

    /// Secret repository constraint/precondition failure.
    #[error("Secret repository constraint: {message}")]
    Constraint {
        /// Description of the constraint failure (non-sensitive).
        message: String,
        /// Logical key/identifier (sanitized).
        key: Option<String>,
    },

    /// Hashing/verification error in secret flow.
    #[error("Secret hashing error: {operation} - {message}")]
    Hashing {
        /// The hashing operation that failed.
        operation: HashingOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// The hashing algorithm used (e.g., `argon2id`) if known.
        algorithm: Option<String>,
        /// Expected hash format (sanitized) if relevant.
        expected_format: Option<String>,
    },
}

impl SecretError {
    /// Construct a repository operation failure.
    pub fn repo_op(
        operation: RepositoryOperation,
        message: impl Into<String>,
        key: Option<String>,
        context: Option<String>,
    ) -> Self {
        SecretError::Repository {
            operation,
            message: message.into(),
            key,
            context,
        }
    }

    /// Construct a not-found error.
    pub fn repo_not_found(key: Option<String>) -> Self {
        SecretError::NotFound { key }
    }

    /// Construct a repository constraint/precondition failure.
    pub fn repo_constraint(message: impl Into<String>, key: Option<String>) -> Self {
        SecretError::Constraint {
            message: message.into(),
            key,
        }
    }

    /// Construct a hashing error with algorithm context.
    pub fn hashing_with_algorithm(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        SecretError::Hashing {
            operation,
            message: message.into(),
            algorithm: Some(algorithm.into()),
            expected_format: None,
        }
    }

    /// Construct a hashing error with full context.
    pub fn hashing_with_context(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        SecretError::Hashing {
            operation,
            message: message.into(),
            algorithm,
            expected_format,
        }
    }

    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            SecretError::Repository { operation, key, .. } => {
                format!("SECR-REPO-{}-{:X}", operation.to_string().to_uppercase(), {
                    // Mix repo category (Secret) and key for stable but short code.
                    format!("{:?}{:?}", RepositoryType::Secret, key).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            SecretError::NotFound { key } => {
                format!("SECR-REPO-NOTFOUND-{:X}", {
                    format!("{:?}{:?}", RepositoryType::Secret, key).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            SecretError::Constraint { key, .. } => {
                format!("SECR-REPO-CONSTRAINT-{:X}", {
                    format!("{:?}{:?}", RepositoryType::Secret, key).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            SecretError::Hashing {
                operation,
                algorithm,
                ..
            } => {
                format!("SECR-HASH-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, algorithm).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for SecretError {
    fn user_message(&self) -> String {
        match self {
            SecretError::Repository { .. } => {
                "There's an issue with the security system. Please try again or contact support if the problem continues.".to_string()
            }
            SecretError::NotFound { .. } => {
                "We couldn't find the requested security information. Please sign in again or contact support if this persists.".to_string()
            }
            SecretError::Constraint { .. } => {
                "We couldn't complete this request due to a security constraint. Please try again later.".to_string()
            }
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash => "There's an issue with the security processing system. Please try again in a moment.".to_string(),
                HashingOperation::Verify => "We couldn't verify your credentials due to a technical issue. Please try signing in again.".to_string(),
                HashingOperation::GenerateSalt => "There's a problem with the security system setup. Please contact support.".to_string(),
                HashingOperation::UpdateHash => "We couldn't update your security information. Please try again or contact support.".to_string(),
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            SecretError::Repository {
                operation,
                message,
                key,
                context,
            } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                let ctx_s = context
                    .as_ref()
                    .map(|c| format!(" [Context: {}]", c))
                    .unwrap_or_default();
                format!(
                    "Secret repository ({}) operation failed: {}{}{}",
                    operation, message, key_s, ctx_s
                )
            }
            SecretError::NotFound { key } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                format!("Secret not found{}", key_s)
            }
            SecretError::Constraint { message, key } => {
                let key_s = key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                format!("Secret repository constraint: {}{}", message, key_s)
            }
            SecretError::Hashing {
                operation,
                message,
                algorithm,
                expected_format,
            } => {
                let algo_s = algorithm
                    .as_ref()
                    .map(|a| format!(" [Algorithm: {}]", a))
                    .unwrap_or_default();
                let exp_s = expected_format
                    .as_ref()
                    .map(|e| format!(" [Expected: {}]", e))
                    .unwrap_or_default();
                format!(
                    "Secret hashing {} failed: {}{}{}",
                    operation, message, algo_s, exp_s
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            // Secret repository issues are generally higher severity
            SecretError::Repository { .. } => ErrorSeverity::Critical,
            SecretError::NotFound { .. } => ErrorSeverity::Critical,
            SecretError::Constraint { .. } => ErrorSeverity::Error,
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::GenerateSalt => ErrorSeverity::Critical,
                HashingOperation::Verify => ErrorSeverity::Critical,
                HashingOperation::UpdateHash => ErrorSeverity::Error,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            SecretError::Repository { .. } => vec![
                "Do not retry password or secret operations repeatedly".to_string(),
                "Wait a moment and try again".to_string(),
                "Contact our support team if the issue persists".to_string(),
            ],
            SecretError::NotFound { .. } => vec![
                "Sign in again to create or refresh your session".to_string(),
                "Clear your browser cookies and try again".to_string(),
                "Contact support if your secret should exist".to_string(),
            ],
            SecretError::Constraint { .. } => vec![
                "Review your input for constraint issues".to_string(),
                "Try your request again after correcting the input".to_string(),
                "Contact support if security constraints are unclear".to_string(),
            ],
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::GenerateSalt => vec![
                    "This is a critical security system error".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not retry operations that involve password or secret changes".to_string(),
                ],
                HashingOperation::Verify => vec![
                    "Double-check your password for typos".to_string(),
                    "Ensure Caps Lock is not accidentally enabled".to_string(),
                    "If you're certain your password is correct, contact support".to_string(),
                    "Try using password recovery if verification continues to fail".to_string(),
                ],
                HashingOperation::UpdateHash => vec![
                    "Try updating your password again in a few minutes".to_string(),
                    "Ensure your new password meets all security requirements".to_string(),
                    "Contact support if password updates continue to fail".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            SecretError::Repository { .. } => false, // avoid repeated secret ops
            SecretError::NotFound { .. } => false,
            SecretError::Constraint { .. } => false,
            SecretError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::GenerateSalt => false,
                HashingOperation::Verify => true, // user can correct input
                HashingOperation::UpdateHash => true, // may succeed on retry
            },
        }
    }
}
