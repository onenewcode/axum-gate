//! Application layer error types for service orchestration failures.
//!
//! This module contains error types that represent failures in application
//! services, use case orchestration, and business workflow coordination.
//!
//! All application errors implement `UserFriendlyError` to provide appropriate
//! messaging for end users, developers, and support teams while maintaining
//! security and consistency.

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
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

    /// Service coordination failure
    #[error("Service coordination error: {service} - {message}")]
    ServiceCoordination {
        /// The service that failed
        service: String,
        /// Description of the coordination failure
        message: String,
        /// The operation that was being coordinated
        operation: Option<String>,
        /// Related entity ID
        entity_id: Option<String>,
    },

    /// Validation failure in application logic
    #[error("Validation error: {field} - {message}")]
    Validation {
        /// The field or input that failed validation
        field: String,
        /// Validation failure message
        message: String,
        /// The invalid value (sanitized for security)
        invalid_value: Option<String>,
        /// Expected format or constraints
        expected: Option<String>,
    },

    /// Workflow state transition error
    #[error("Workflow error: {workflow} - {message}")]
    Workflow {
        /// The workflow that failed
        workflow: String,
        /// Description of the workflow failure
        message: String,
        /// Current state of the workflow
        current_state: Option<String>,
        /// Attempted transition
        attempted_transition: Option<String>,
    },
}

/// Specific authentication error types
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// Invalid credentials provided
    #[error("Invalid credentials provided")]
    InvalidCredentials,

    /// Session expired or invalid
    #[error("Session expired")]
    SessionExpired,

    /// Account locked due to security policy
    #[error("Account temporarily locked")]
    AccountLocked,

    /// Multi-factor authentication required
    #[error("Multi-factor authentication required")]
    MfaRequired,

    /// Authentication rate limit exceeded
    #[error("Too many authentication attempts")]
    RateLimitExceeded,
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
    /// Query account operation
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

    /// Create a service coordination error
    pub fn service_coordination(
        service: impl Into<String>,
        message: impl Into<String>,
        operation: Option<String>,
        entity_id: Option<String>,
    ) -> Self {
        ApplicationError::ServiceCoordination {
            service: service.into(),
            message: message.into(),
            operation,
            entity_id,
        }
    }

    /// Create a validation error
    pub fn validation(
        field: impl Into<String>,
        message: impl Into<String>,
        invalid_value: Option<String>,
        expected: Option<String>,
    ) -> Self {
        ApplicationError::Validation {
            field: field.into(),
            message: message.into(),
            invalid_value,
            expected,
        }
    }

    /// Create a workflow error
    pub fn workflow(
        workflow: impl Into<String>,
        message: impl Into<String>,
        current_state: Option<String>,
        attempted_transition: Option<String>,
    ) -> Self {
        ApplicationError::Workflow {
            workflow: workflow.into(),
            message: message.into(),
            current_state,
            attempted_transition,
        }
    }

    /// Generate a deterministic support code based on error content
    fn generate_support_code(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            ApplicationError::AccountService {
                operation,
                account_id,
                ..
            } => {
                format!("ACCOUNT-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, account_id).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            ApplicationError::Authentication { auth_error, .. } => match auth_error {
                AuthenticationError::InvalidCredentials => "AUTH-INVALID-CREDS".to_string(),
                AuthenticationError::SessionExpired => "AUTH-SESSION-EXPIRED".to_string(),
                AuthenticationError::AccountLocked => "AUTH-ACCOUNT-LOCKED".to_string(),
                AuthenticationError::MfaRequired => "AUTH-MFA-REQUIRED".to_string(),
                AuthenticationError::RateLimitExceeded => "AUTH-RATE-LIMITED".to_string(),
            },
            ApplicationError::ServiceCoordination { service, .. } => {
                service.hash(&mut hasher);
                format!("SERVICE-COORD-{:X}", hasher.finish() % 10000)
            }
            ApplicationError::Validation { field, .. } => {
                field.hash(&mut hasher);
                format!("VALIDATION-{:X}", hasher.finish() % 10000)
            }
            ApplicationError::Workflow { workflow, .. } => {
                workflow.hash(&mut hasher);
                format!("WORKFLOW-{:X}", hasher.finish() % 10000)
            }
        }
    }
}

impl UserFriendlyError for ApplicationError {
    fn user_message(&self) -> String {
        match self {
            ApplicationError::AccountService { operation, .. } => {
                match operation {
                    AccountOperation::Create => "We couldn't create your account right now. Please try again in a moment, or contact our support team if the problem continues.".to_string(),
                    AccountOperation::Update => "We couldn't update your account settings. Please try again, or contact support if you continue to experience issues.".to_string(),
                    AccountOperation::Delete => "We couldn't delete your account at this time. Please try again later, or contact our support team for assistance.".to_string(),
                    AccountOperation::Query => "We're having trouble accessing your account information. Please refresh the page or try signing in again.".to_string(),
                    AccountOperation::Activate => "We couldn't activate your account. Please check your email for activation instructions or contact our support team.".to_string(),
                    AccountOperation::Deactivate => "We couldn't deactivate your account right now. Please try again later or contact support for assistance.".to_string(),
                }
            }
            ApplicationError::Authentication { auth_error, .. } => {
                match auth_error {
                    AuthenticationError::InvalidCredentials => "The username or password you entered is incorrect. Please check your credentials and try again.".to_string(),
                    AuthenticationError::SessionExpired => "Your session has expired for security reasons. Please sign in again to continue.".to_string(),
                    AuthenticationError::AccountLocked => "Your account has been temporarily locked for security reasons. Please try again later or contact our support team.".to_string(),
                    AuthenticationError::MfaRequired => "Additional verification is required to sign in. Please complete the multi-factor authentication process.".to_string(),
                    AuthenticationError::RateLimitExceeded => "Too many sign-in attempts detected. Please wait a few minutes before trying again.".to_string(),
                }
            }
            ApplicationError::ServiceCoordination { .. } => {
                "We're experiencing technical difficulties with our services. Please try again in a few minutes, or contact support if the issue persists.".to_string()
            }
            ApplicationError::Validation { field, expected, .. } => {
                let field_friendly = field.replace('_', " ").to_lowercase();
                match expected {
                    Some(exp) => format!("The {} you entered is not valid. Please ensure it meets the required format: {}.", field_friendly, exp),
                    None => format!("The {} you entered is not valid. Please check the format and try again.", field_friendly),
                }
            }
            ApplicationError::Workflow { .. } => {
                "This action cannot be completed at this time due to the current status of your request. Please try again later or contact support for assistance.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            ApplicationError::AccountService {
                operation,
                message,
                account_id,
            } => {
                let account_context = account_id
                    .as_ref()
                    .map(|id| format!(" [Account: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Account service {} operation failed: {}{}",
                    operation, message, account_context
                )
            }
            ApplicationError::Authentication {
                auth_error,
                context,
            } => {
                let context_info = context
                    .as_ref()
                    .map(|c| format!(" Context: {}", c))
                    .unwrap_or_default();
                format!("Authentication failure: {}.{}", auth_error, context_info)
            }
            ApplicationError::ServiceCoordination {
                service,
                message,
                operation,
                entity_id,
            } => {
                let operation_context = operation
                    .as_ref()
                    .map(|op| format!(" [Operation: {}]", op))
                    .unwrap_or_default();
                let entity_context = entity_id
                    .as_ref()
                    .map(|id| format!(" [Entity: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Service coordination failure in {}: {}{}{}",
                    service, message, operation_context, entity_context
                )
            }
            ApplicationError::Validation {
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
                    "Validation failed for field '{}': {}{}{}",
                    field, message, value_context, expected_context
                )
            }
            ApplicationError::Workflow {
                workflow,
                message,
                current_state,
                attempted_transition,
            } => {
                let state_context = current_state
                    .as_ref()
                    .map(|s| format!(" [Current: {}]", s))
                    .unwrap_or_default();
                let transition_context = attempted_transition
                    .as_ref()
                    .map(|t| format!(" [Attempted: {}]", t))
                    .unwrap_or_default();
                format!(
                    "Workflow '{}' error: {}{}{}",
                    workflow, message, state_context, transition_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.generate_support_code()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            ApplicationError::AccountService { operation, .. } => match operation {
                AccountOperation::Delete => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            ApplicationError::Authentication { auth_error, .. } => match auth_error {
                AuthenticationError::AccountLocked => ErrorSeverity::Critical,
                AuthenticationError::InvalidCredentials => ErrorSeverity::Warning,
                AuthenticationError::SessionExpired => ErrorSeverity::Info,
                _ => ErrorSeverity::Error,
            },
            ApplicationError::ServiceCoordination { .. } => ErrorSeverity::Error,
            ApplicationError::Validation { .. } => ErrorSeverity::Warning,
            ApplicationError::Workflow { .. } => ErrorSeverity::Warning,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            ApplicationError::AccountService { operation, .. } => match operation {
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
            ApplicationError::Authentication { auth_error, .. } => match auth_error {
                AuthenticationError::InvalidCredentials => vec![
                    "Double-check your username and password for typos".to_string(),
                    "Ensure Caps Lock is not accidentally enabled".to_string(),
                    "Use the 'Forgot Password' link if you can't remember your password"
                        .to_string(),
                    "Contact support if you're sure your credentials are correct".to_string(),
                ],
                AuthenticationError::SessionExpired => vec![
                    "Sign in again to continue using the application".to_string(),
                    "For security, sessions automatically expire after a period of inactivity"
                        .to_string(),
                ],
                AuthenticationError::AccountLocked => vec![
                    "Wait 15-30 minutes before attempting to sign in again".to_string(),
                    "Contact our support team if you need immediate access".to_string(),
                    "Review our security policies to understand account lockout procedures"
                        .to_string(),
                ],
                AuthenticationError::MfaRequired => vec![
                    "Complete the multi-factor authentication step".to_string(),
                    "Check your phone or email for the verification code".to_string(),
                    "Contact support if you're not receiving verification codes".to_string(),
                ],
                AuthenticationError::RateLimitExceeded => vec![
                    "Wait 5-10 minutes before trying to sign in again".to_string(),
                    "Use the 'Forgot Password' feature if you're unsure of your credentials"
                        .to_string(),
                    "Contact support if you believe this restriction is in error".to_string(),
                ],
            },
            ApplicationError::ServiceCoordination { .. } => vec![
                "Wait a few minutes and try your request again".to_string(),
                "Check our status page for any ongoing service issues".to_string(),
                "Try refreshing the page or restarting the application".to_string(),
                "Contact support if the problem persists".to_string(),
            ],
            ApplicationError::Validation { expected, .. } => {
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
            ApplicationError::Workflow { .. } => vec![
                "Check the current status of your request or application".to_string(),
                "Ensure all previous steps have been completed successfully".to_string(),
                "Wait for any pending processes to complete before trying again".to_string(),
                "Contact support for assistance with workflow requirements".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            ApplicationError::AccountService { operation, .. } => {
                match operation {
                    AccountOperation::Delete => false, // Requires careful handling
                    _ => true,
                }
            }
            ApplicationError::Authentication { auth_error, .. } => {
                match auth_error {
                    AuthenticationError::InvalidCredentials => true,
                    AuthenticationError::SessionExpired => true,
                    AuthenticationError::AccountLocked => false, // Time-based unlock
                    AuthenticationError::MfaRequired => true,
                    AuthenticationError::RateLimitExceeded => false, // Time-based retry
                }
            }
            ApplicationError::ServiceCoordination { .. } => true, // Infrastructure issues often resolve
            ApplicationError::Validation { .. } => true,          // User can correct input
            ApplicationError::Workflow { .. } => true,            // Workflow state might change
        }
    }
}
