#![deny(missing_docs)]

//! Authorization-category native errors.
//!
//! This module defines category-native errors for authorization (authz) concerns,
//! including permission format validation, permission hash collisions, and access
//! hierarchy violations. It replaces prior layer-oriented re-exports with a
//! dedicated `AuthzError` enum, aligned with the crate's categorical DDD structure.
//!
//! # Overview
//! - `AuthzError`: category-native error enum for authorization
//! - Convenience constructors: `invalid`, `collision`, `hierarchy_violation`
//!
//! # Examples
//!
//! Detect a permission hash collision:
//! ```rust
//! use axum_gate::errors::authz::AuthzError;
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = AuthzError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("AUTHZ-PERM-COLLISION-"));
//! assert_eq!(err.severity(), axum_gate::errors::ErrorSeverity::Critical);
//! ```
//!
//! Validate permission format:
//! ```rust
//! use axum_gate::errors::authz::AuthzError;
//!
//! let err = AuthzError::invalid(
//!     "invalid-permission",
//!     "missing ':' separator",
//!     Some("domain:action".into()),
//! );
//! assert!(matches!(err, AuthzError::InvalidPermission { .. }));
//! ```
//!
//! Access hierarchy violations:
//! ```rust
//! use axum_gate::errors::authz::AuthzError;
//!
//! let err = AuthzError::hierarchy_violation(
//!     "role_inheritance",
//!     "user lacks required supervisor role",
//!     Some("user-123".into()),
//!     Some("resource-xyz".into()),
//! );
//! assert!(matches!(err, AuthzError::AccessHierarchyViolation { .. }));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Authorization-category native errors.
///
/// Use these errors in authorization flows to model permission format problems,
/// permission hash collisions, and access hierarchy violations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// Permission collision detected when multiple permissions hash to the same value.
    #[error("Permission collision: {collision_count} permissions map to hash {hash_id}")]
    PermissionCollision {
        /// Number of permissions that collide.
        collision_count: usize,
        /// The 64-bit hash ID that has collisions.
        hash_id: u64,
        /// List of permission names that collide.
        permissions: Vec<String>,
    },

    /// Invalid permission format or structure.
    #[error("Invalid permission format: {permission} - {reason}")]
    InvalidPermission {
        /// The invalid permission string.
        permission: String,
        /// Reason why the permission is invalid.
        reason: String,
        /// Expected format or pattern.
        expected: Option<String>,
    },

    /// Access hierarchy violation (e.g., missing supervisor role for a required role).
    #[error("Access hierarchy violation: {violation_type} - {details}")]
    AccessHierarchyViolation {
        /// Type of hierarchy violation.
        violation_type: String,
        /// Detailed description of the violation.
        details: String,
        /// The user ID involved in the violation.
        user_id: Option<String>,
        /// The resource being accessed.
        resource: Option<String>,
    },
}

impl AuthzError {
    /// Create a permission collision error with collision details.
    ///
    /// This constructor calculates the `collision_count` from the provided list.
    pub fn collision(hash_id: u64, permissions: Vec<String>) -> Self {
        AuthzError::PermissionCollision {
            collision_count: permissions.len(),
            hash_id,
            permissions,
        }
    }

    /// Create an invalid permission format error.
    pub fn invalid(
        permission: impl Into<String>,
        reason: impl Into<String>,
        expected: Option<String>,
    ) -> Self {
        AuthzError::InvalidPermission {
            permission: permission.into(),
            reason: reason.into(),
            expected,
        }
    }

    /// Create an access hierarchy violation error.
    pub fn hierarchy_violation(
        violation_type: impl Into<String>,
        details: impl Into<String>,
        user_id: Option<String>,
        resource: Option<String>,
    ) -> Self {
        AuthzError::AccessHierarchyViolation {
            violation_type: violation_type.into(),
            details: details.into(),
            user_id,
            resource,
        }
    }

    /// Deterministic, category-specific support code for this error.
    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            AuthzError::PermissionCollision { hash_id, .. } => {
                format!("AUTHZ-PERM-COLLISION-{}", hash_id)
            }
            AuthzError::InvalidPermission { permission, .. } => {
                permission.hash(&mut hasher);
                format!("AUTHZ-PERM-INVALID-{:X}", hasher.finish() % 10000)
            }
            AuthzError::AccessHierarchyViolation { violation_type, .. } => {
                violation_type.hash(&mut hasher);
                format!("AUTHZ-HIER-{:X}", hasher.finish() % 10000)
            }
        }
    }
}

impl UserFriendlyError for AuthzError {
    fn user_message(&self) -> String {
        match self {
            AuthzError::PermissionCollision { .. } => {
                "There's a technical issue with your account permissions. Our support team has been notified and will resolve this shortly. Please contact support if you need immediate assistance.".to_string()
            }
            AuthzError::InvalidPermission { .. } => {
                "Your account permissions need to be updated. Please contact our support team who can help resolve this for you.".to_string()
            }
            AuthzError::AccessHierarchyViolation { .. } => {
                "You don't have the necessary permissions to access this resource. If you believe you should have access, please contact your administrator or our support team.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            AuthzError::PermissionCollision {
                collision_count,
                hash_id,
                permissions,
            } => {
                format!(
                    "Permission collision detected: {} permissions [{}] map to hash ID {}. This indicates a critical hash collision in the permission system requiring immediate administrator attention.",
                    collision_count,
                    permissions.join(", "),
                    hash_id
                )
            }
            AuthzError::InvalidPermission {
                permission,
                reason,
                expected,
            } => {
                let format_hint = expected
                    .as_ref()
                    .map(|f| format!(" Expected format: '{}'", f))
                    .unwrap_or_default();
                format!(
                    "Invalid permission format detected: '{}'. Validation failed: {}.{}",
                    permission, reason, format_hint
                )
            }
            AuthzError::AccessHierarchyViolation {
                violation_type,
                details,
                user_id,
                resource,
            } => {
                let user_context = user_id
                    .as_ref()
                    .map(|id| format!(" [User: {}]", id))
                    .unwrap_or_default();
                let resource_context = resource
                    .as_ref()
                    .map(|r| format!(" [Resource: {}]", r))
                    .unwrap_or_default();
                format!(
                    "Access hierarchy violation: {} - {}{}{}",
                    violation_type, details, user_context, resource_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.support_code_inner()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            AuthzError::PermissionCollision { .. } => ErrorSeverity::Critical,
            AuthzError::InvalidPermission { .. } => ErrorSeverity::Error,
            AuthzError::AccessHierarchyViolation { .. } => ErrorSeverity::Warning,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            AuthzError::PermissionCollision { .. } => vec![
                "Contact our support team immediately with the reference code below".to_string(),
                "Do not attempt to retry this operation".to_string(),
                "This is a critical system issue requiring immediate administrator attention"
                    .to_string(),
            ],
            AuthzError::InvalidPermission { expected, .. } => {
                let mut actions = vec![
                    "Contact your system administrator to review and update your permissions"
                        .to_string(),
                    "Verify you have the correct access level for your role".to_string(),
                ];
                if let Some(format) = expected {
                    actions.push(format!(
                        "Ensure permissions follow this format: '{}'",
                        format
                    ));
                }
                actions.push("If this problem persists, contact our support team".to_string());
                actions
            }
            AuthzError::AccessHierarchyViolation { .. } => vec![
                "Check that you have the necessary permissions for this resource".to_string(),
                "Contact your administrator if you believe you should have access".to_string(),
                "Verify you are signed in with the correct account".to_string(),
                "Try refreshing your session by signing out and back in".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            AuthzError::PermissionCollision { .. } => false, // Critical system-level issue
            AuthzError::InvalidPermission { .. } => false,   // Requires admin configuration change
            AuthzError::AccessHierarchyViolation { .. } => false, // Permissions issue
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Deprecated re-exports (migration aid)                                       */
/* -------------------------------------------------------------------------- */
