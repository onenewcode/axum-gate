//! Account-category native errors.
//!
//! This module provides category-native error types for the Accounts domain,
//! decoupled from layered/hexagonal naming. Use these types directly in
//! account-related services, repositories, and handlers.
//!
//! # Overview
//! - `AccountsError`: domain-specific error enum for account operations
//! - `AccountOperation`: operation discriminator used by `AccountsError`
//!
//! # Examples
//! Basic construction and user-facing message extraction:
//! ```rust
//! use axum_gate::errors::accounts::{AccountsError, AccountOperation};
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AccountsError::operation(
//!     AccountOperation::Create,
//!     "failed to persist account",
//!     Some("user-123".into()),
//! );
//!
//! assert!(err.user_message().contains("couldn't create your account"));
//! assert!(err.developer_message().contains("Account operation create failed"));
//! assert!(err.support_code().starts_with("ACCT-"));
//! ```
//!
//! Validation example:
//! ```rust
//! use axum_gate::errors::accounts::AccountsError;
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AccountsError::validation("email", "invalid format", Some("not-an-email".into()), Some("name@example.com".into()));
//! assert!(matches!(err.severity(), axum_gate::errors::ErrorSeverity::Warning));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Supported account operations for structured error reporting.
#[derive(Debug, Clone)]
pub enum AccountOperation {
    /// Create account operation
    Create,
    /// Update account operation
    Update,
    /// Delete account operation
    Delete,
    /// Query/read account operation
    Query,
    /// Activate account operation
    Activate,
    /// Deactivate account operation
    Deactivate,
}

impl fmt::Display for AccountOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountOperation::Create => write!(f, "create"),
            AccountOperation::Update => write!(f, "update"),
            AccountOperation::Delete => write!(f, "delete"),
            AccountOperation::Query => write!(f, "query"),
            AccountOperation::Activate => write!(f, "activate"),
            AccountOperation::Deactivate => write!(f, "deactivate"),
        }
    }
}

/// Accounts domain errors (category-native).
///
/// These errors cover account-related operation failures, validation, and workflow concerns.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccountsError {
    /// An account operation failed.
    #[error("Account operation {operation} failed: {message}")]
    Operation {
        /// The account operation that failed.
        operation: AccountOperation,
        /// Description of the failure (non-sensitive).
        message: String,
        /// Optional related account identifier (sanitized).
        account_id: Option<String>,
    },

    /// Account-specific validation failure.
    #[error("Account validation error: {field} - {message}")]
    Validation {
        /// The field or input that failed validation.
        field: String,
        /// Validation failure message (non-sensitive).
        message: String,
        /// The invalid value (sanitized) if applicable.
        invalid_value: Option<String>,
        /// Expected format or constraints (non-sensitive).
        expected: Option<String>,
    },

    /// Account workflow/state transition failure.
    #[error("Account workflow error: {message}")]
    Workflow {
        /// Description of the workflow failure.
        message: String,
        /// Current state of the workflow (if known).
        current_state: Option<String>,
        /// Attempted transition (if known).
        attempted_transition: Option<String>,
        /// Related account identifier (sanitized).
        account_id: Option<String>,
    },
}

impl AccountsError {
    /// Construct an operation failure.
    pub fn operation(
        operation: AccountOperation,
        message: impl Into<String>,
        account_id: Option<String>,
    ) -> Self {
        AccountsError::Operation {
            operation,
            message: message.into(),
            account_id,
        }
    }

    /// Construct a validation failure.
    pub fn validation(
        field: impl Into<String>,
        message: impl Into<String>,
        invalid_value: Option<String>,
        expected: Option<String>,
    ) -> Self {
        AccountsError::Validation {
            field: field.into(),
            message: message.into(),
            invalid_value,
            expected,
        }
    }

    /// Construct a workflow failure.
    pub fn workflow(
        message: impl Into<String>,
        current_state: Option<String>,
        attempted_transition: Option<String>,
        account_id: Option<String>,
    ) -> Self {
        AccountsError::Workflow {
            message: message.into(),
            current_state,
            attempted_transition,
            account_id,
        }
    }

    /// Deterministic, category-specific support code.
    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            AccountsError::Operation {
                operation,
                account_id,
                ..
            } => {
                format!("ACCT-OP-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, account_id).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            AccountsError::Validation { field, .. } => {
                field.hash(&mut hasher);
                format!("ACCT-VALID-{:X}", hasher.finish() % 10000)
            }
            AccountsError::Workflow {
                current_state,
                attempted_transition,
                account_id,
                ..
            } => {
                format!("ACCT-WORKFLOW-{:X}", {
                    format!(
                        "{:?}{:?}{:?}",
                        current_state, attempted_transition, account_id
                    )
                    .hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for AccountsError {
    fn user_message(&self) -> String {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Create => "We couldn't create your account right now. Please try again in a moment, or contact our support team if the problem continues.".to_string(),
                AccountOperation::Update => "We couldn't update your account settings. Please try again, or contact support if you continue to experience issues.".to_string(),
                AccountOperation::Delete => "We couldn't delete your account at this time. Please try again later, or contact our support team for assistance.".to_string(),
                AccountOperation::Query => "We're having trouble accessing your account information. Please refresh the page or try signing in again.".to_string(),
                AccountOperation::Activate => "We couldn't activate your account. Please check your email for activation instructions or contact our support team.".to_string(),
                AccountOperation::Deactivate => "We couldn't deactivate your account right now. Please try again later or contact support for assistance.".to_string(),
            },
            AccountsError::Validation { field, expected, .. } => {
                let field_friendly = field.replace('_', " ").to_lowercase();
                match expected {
                    Some(exp) => format!("The {} you entered is not valid. Please ensure it meets the required format: {}.", field_friendly, exp),
                    None => format!("The {} you entered is not valid. Please check the format and try again.", field_friendly),
                }
            }
            AccountsError::Workflow { .. } => {
                "This action cannot be completed at this time due to the current status of your account. Please try again later or contact support for assistance.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AccountsError::Operation {
                operation,
                message,
                account_id,
            } => {
                let account_context = account_id
                    .as_ref()
                    .map(|id| format!(" [Account: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Account operation {} failed: {}{}",
                    operation, message, account_context
                )
            }
            AccountsError::Validation {
                field,
                message,
                invalid_value,
                expected,
            } => {
                let value_context = invalid_value
                    .as_ref()
                    .map(|v| format!(" [Invalid: {}]", v))
                    .unwrap_or_default();
                let expected_context = expected
                    .as_ref()
                    .map(|e| format!(" [Expected: {}]", e))
                    .unwrap_or_default();
                format!(
                    "Account validation failed for field '{}': {}{}{}",
                    field, message, value_context, expected_context
                )
            }
            AccountsError::Workflow {
                message,
                current_state,
                attempted_transition,
                account_id,
            } => {
                let state_context = current_state
                    .as_ref()
                    .map(|s| format!(" [Current: {}]", s))
                    .unwrap_or_default();
                let transition_context = attempted_transition
                    .as_ref()
                    .map(|t| format!(" [Attempted: {}]", t))
                    .unwrap_or_default();
                let account_context = account_id
                    .as_ref()
                    .map(|id| format!(" [Account: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Account workflow error: {}{}{}{}",
                    message, state_context, transition_context, account_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Delete => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            AccountsError::Validation { .. } => ErrorSeverity::Warning,
            AccountsError::Workflow { .. } => ErrorSeverity::Warning,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Create => vec![
                    "Wait a moment and try creating your account again".to_string(),
                    "Ensure all required fields are filled out correctly".to_string(),
                    "Check your email for any verification requirements".to_string(),
                    "Contact our support team if the problem continues".to_string(),
                ],
                AccountOperation::Update => vec![
                    "Try saving your changes again".to_string(),
                    "Refresh the page and make your changes again".to_string(),
                    "Contact support if you continue to have issues".to_string(),
                ],
                AccountOperation::Delete => vec![
                    "Contact our support team to assist with account deletion".to_string(),
                    "Ensure you have completed any required pre-deletion steps".to_string(),
                    "This operation may be temporarily unavailable for security reasons"
                        .to_string(),
                ],
                AccountOperation::Query => vec![
                    "Refresh the page or try signing out and back in".to_string(),
                    "Clear your browser cache and cookies".to_string(),
                    "Try accessing your account from a different device or browser".to_string(),
                ],
                AccountOperation::Activate => vec![
                    "Check your email for the account activation link".to_string(),
                    "Ensure you clicked the most recent activation link".to_string(),
                    "Contact support if you haven't received an activation email".to_string(),
                ],
                AccountOperation::Deactivate => vec![
                    "Try again in a few minutes".to_string(),
                    "Contact support if you need immediate account deactivation".to_string(),
                ],
            },
            AccountsError::Validation { expected, .. } => {
                let mut actions = vec![
                    "Review the information you entered and correct any errors".to_string(),
                    "Ensure all required fields are completed".to_string(),
                ];
                if let Some(exp) = expected {
                    actions.push(format!("Make sure your input follows this format: {}", exp));
                }
                actions.push(
                    "Contact support if you need help understanding the requirements".to_string(),
                );
                actions
            }
            AccountsError::Workflow { .. } => vec![
                "Check the current status of your account".to_string(),
                "Ensure all previous steps have been completed successfully".to_string(),
                "Wait for any pending processes to complete before trying again".to_string(),
                "Contact support for assistance with workflow requirements".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AccountsError::Operation { operation, .. } => match operation {
                AccountOperation::Delete => false,
                _ => true,
            },
            AccountsError::Validation { .. } => true,
            AccountsError::Workflow { .. } => true,
        }
    }
}
