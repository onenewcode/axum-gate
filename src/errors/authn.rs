#![deny(missing_docs)]

/*!
Authentication-category native errors.

This module defines category-native errors for authentication (authn) flows
(login, logout, session renewal), decoupled from the legacy layered naming.
It reuses the existing `AuthenticationError` variants as the leaf error kinds.

# Overview

- `AuthnError`: category-native error enum for authentication flows
- `AuthenticationError`: reused leaf error variants describing authn failures

# Examples

Basic construction and user-facing message extraction:

```rust
use axum_gate::errors::authn::{AuthnError, AuthenticationError};
use axum_gate::errors::UserFriendlyError;

let err = AuthnError::from_authentication(AuthenticationError::InvalidCredentials, Some("login form".into()));
assert!(err.user_message().contains("username or password"));
assert!(err.developer_message().contains("Authentication failure"));
assert!(err.support_code().starts_with("AUTHN-"));
```

Convenience constructors:

```rust
use axum_gate::errors::authn::AuthnError;

let _ = AuthnError::invalid_credentials(Some("signin".into()));
let _ = AuthnError::session_expired(None);
let _ = AuthnError::account_locked(Some("too many attempts".into()));
let _ = AuthnError::mfa_required(None);
let _ = AuthnError::rate_limit_exceeded(None);
```
*/

use crate::errors::{ErrorSeverity, UserFriendlyError};

use thiserror::Error;

/// Leaf authentication error variants reused by the authn category.
/// Specific authentication error types for authentication flows.
#[derive(Debug, thiserror::Error)]
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

/// Category-native authentication error.
///
/// Wraps `AuthenticationError` and provides category-oriented constructors,
/// user-friendly messaging, support codes, severity, and retryability.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// Authentication flow failure (e.g., invalid credentials, expired session).
    #[error("Authentication error: {error}")]
    Authentication {
        /// The specific authentication failure kind.
        #[source]
        error: AuthenticationError,
        /// Optional context about where/how the failure occurred (non-sensitive).
        context: Option<String>,
    },
}

impl AuthnError {
    /// Construct from a leaf `AuthenticationError` with optional context.
    pub fn from_authentication(error: AuthenticationError, context: Option<String>) -> Self {
        AuthnError::Authentication { error, context }
    }

    /// Invalid credentials were provided.
    pub fn invalid_credentials(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::InvalidCredentials, context)
    }

    /// Session has expired or is otherwise invalid.
    pub fn session_expired(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::SessionExpired, context)
    }

    /// Account has been temporarily locked due to security policy.
    pub fn account_locked(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::AccountLocked, context)
    }

    /// Multi-factor authentication is required to proceed.
    pub fn mfa_required(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::MfaRequired, context)
    }

    /// Authentication rate limit has been exceeded.
    pub fn rate_limit_exceeded(context: Option<String>) -> Self {
        Self::from_authentication(AuthenticationError::RateLimitExceeded, context)
    }

    fn support_code_inner(&self) -> String {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => "AUTHN-INVALID-CREDS".to_string(),
                AuthenticationError::SessionExpired => "AUTHN-SESSION-EXPIRED".to_string(),
                AuthenticationError::AccountLocked => "AUTHN-ACCOUNT-LOCKED".to_string(),
                AuthenticationError::MfaRequired => "AUTHN-MFA-REQUIRED".to_string(),
                AuthenticationError::RateLimitExceeded => "AUTHN-RATE-LIMITED".to_string(),
            },
        }
    }
}

impl UserFriendlyError for AuthnError {
    fn user_message(&self) -> String {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => {
                    "The username or password you entered is incorrect. Please check your credentials and try again.".to_string()
                }
                AuthenticationError::SessionExpired => {
                    "Your session has expired for security reasons. Please sign in again to continue.".to_string()
                }
                AuthenticationError::AccountLocked => {
                    "Your account has been temporarily locked for security reasons. Please try again later or contact our support team.".to_string()
                }
                AuthenticationError::MfaRequired => {
                    "Additional verification is required to sign in. Please complete the multi-factor authentication process.".to_string()
                }
                AuthenticationError::RateLimitExceeded => {
                    "Too many sign-in attempts detected. Please wait a few minutes before trying again.".to_string()
                }
            },
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AuthnError::Authentication { error, context } => {
                let context_info = context
                    .as_ref()
                    .map(|c| format!(" Context: {}", c))
                    .unwrap_or_default();
                format!("Authentication failure: {}.{}", error, context_info)
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::AccountLocked => ErrorSeverity::Critical,
                AuthenticationError::InvalidCredentials => ErrorSeverity::Warning,
                AuthenticationError::SessionExpired => ErrorSeverity::Info,
                AuthenticationError::MfaRequired => ErrorSeverity::Error,
                AuthenticationError::RateLimitExceeded => ErrorSeverity::Error,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AuthnError::Authentication { error, .. } => match error {
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
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AuthnError::Authentication { error, .. } => match error {
                AuthenticationError::InvalidCredentials => true,
                AuthenticationError::SessionExpired => true,
                AuthenticationError::AccountLocked => false, // time-based unlock
                AuthenticationError::MfaRequired => true,
                AuthenticationError::RateLimitExceeded => false, // time-based retry
            },
        }
    }
}
