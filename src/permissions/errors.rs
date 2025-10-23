//! Permission-category native errors.
//!
//! This module defines category-native errors for permission concerns
//! (format validation, collision detection, and access hierarchy issues),
//! Use these errors directly in handlers, services, and middleware.
//!
//! # Overview
//!
//! - `PermissionsError`: category-native error enum for permission issues
//!
//! # Examples
//!
//! Detect a permission hash collision:
//! ```rust
//! use axum_gate::errors::permissions::PermissionsError;
//! use axum_gate::errors::UserFriendlyError;
//!
//! let err = PermissionsError::collision(42, vec!["read:alpha".into(), "read:beta".into()]);
//! assert!(err.support_code().starts_with("PERM-COLLISION-"));
//! assert_eq!(err.severity(), axum_gate::errors::ErrorSeverity::Critical);
//! ```
//!
//! Validate permission format:
//! ```rust
//! use axum_gate::errors::permissions::PermissionsError;
//!
//! let err = PermissionsError::invalid(
//!     "invalid-perm",
//!     "missing ':' separator",
//!     Some("domain:action".into()),
//! );
//! assert!(matches!(err, PermissionsError::InvalidFormat { .. }));
//! ```
//!
//! Access hierarchy violations:
//! ```rust
//! use axum_gate::errors::permissions::PermissionsError;
//!
//! let err = PermissionsError::hierarchy_violation(
//!     "role_inheritance",
//!     "user lacks required supervisor role",
//!     Some("user-123".into()),
//!     Some("resource-xyz".into()),
//! );
//! assert!(matches!(err, PermissionsError::HierarchyViolation { .. }));
//! ```

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Category-native permission errors.
///
/// These errors model permission-related problems.
/// Use directly in permission validation and authorization flows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PermissionsError {
    /// Permission collision detected when multiple permissions hash to the same value.
    #[error("Permission collision: {collision_count} permissions map to hash {hash_id}")]
    Collision {
        /// Number of permissions that collide.
        collision_count: usize,
        /// The 64-bit hash ID that has collisions.
        hash_id: u64,
        /// List of permission names that collide.
        permissions: Vec<String>,
    },

    /// Invalid permission format or structure.
    #[error("Invalid permission format: {permission} - {reason}")]
    InvalidFormat {
        /// The invalid permission string.
        permission: String,
        /// Reason why the permission is invalid.
        reason: String,
        /// Expected format or pattern.
        expected: Option<String>,
    },

    /// Access hierarchy violation (e.g., missing supervisor role for a required role).
    #[error("Access hierarchy violation: {violation_type} - {details}")]
    HierarchyViolation {
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

impl PermissionsError {
    /// Create a permission collision error with collision details.
    ///
    /// This constructor calculates the `collision_count` from the provided list.
    pub fn collision(hash_id: u64, permissions: Vec<String>) -> Self {
        PermissionsError::Collision {
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
        PermissionsError::InvalidFormat {
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
        PermissionsError::HierarchyViolation {
            violation_type: violation_type.into(),
            details: details.into(),
            user_id,
            resource,
        }
    }

    /// Generate a deterministic support code based on error content.
    fn support_code_inner(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            PermissionsError::Collision { hash_id, .. } => {
                format!("PERM-COLLISION-{}", hash_id)
            }
            PermissionsError::InvalidFormat { permission, .. } => {
                permission.hash(&mut hasher);
                format!("PERM-INVALID-{:X}", hasher.finish() % 10000)
            }
            PermissionsError::HierarchyViolation { violation_type, .. } => {
                violation_type.hash(&mut hasher);
                format!("PERM-HIER-{:X}", hasher.finish() % 10000)
            }
        }
    }
}

impl UserFriendlyError for PermissionsError {
    fn user_message(&self) -> String {
        match self {
            PermissionsError::Collision { .. } => {
                "There's a technical issue with your account permissions. Our support team has been notified and will resolve this shortly. Please contact support if you need immediate assistance.".to_string()
            }
            PermissionsError::InvalidFormat { .. } => {
                "Your account permissions need to be updated. Please contact our support team who can help resolve this for you.".to_string()
            }
            PermissionsError::HierarchyViolation { .. } => {
                "You don't have the necessary permissions to access this resource. If you believe you should have access, please contact your administrator or our support team.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            PermissionsError::Collision {
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
            PermissionsError::InvalidFormat {
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
            PermissionsError::HierarchyViolation {
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
            PermissionsError::Collision { .. } => ErrorSeverity::Critical,
            PermissionsError::InvalidFormat { .. } => ErrorSeverity::Error,
            PermissionsError::HierarchyViolation { .. } => ErrorSeverity::Warning,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            PermissionsError::Collision { .. } => vec![
                "Contact our support team immediately with the reference code below".to_string(),
                "Do not attempt to retry this operation".to_string(),
                "This is a critical system issue requiring immediate administrator attention"
                    .to_string(),
            ],
            PermissionsError::InvalidFormat { expected, .. } => {
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
            PermissionsError::HierarchyViolation { .. } => vec![
                "Check that you have the necessary permissions for this resource".to_string(),
                "Contact your administrator if you believe you should have access".to_string(),
                "Verify you are signed in with the correct account".to_string(),
                "Try refreshing your session by signing out and back in".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            PermissionsError::Collision { .. } => false, // Critical system-level issue
            PermissionsError::InvalidFormat { .. } => false, // Requires admin configuration change
            PermissionsError::HierarchyViolation { .. } => false, // Permissions issue
        }
    }
}
