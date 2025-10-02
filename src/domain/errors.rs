//! Domain layer error types for business logic violations.
//!
//! This module contains error types that represent violations of business rules
//! and domain logic. These errors are independent of external systems and
//! represent pure domain concerns.
//!
//! All domain errors implement `UserFriendlyError` to provide appropriate
//! messaging for end users, developers, and support teams while maintaining
//! security and consistency.

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Domain layer errors representing business rule violations and domain logic failures.
///
/// These errors are independent of external systems and represent pure business
/// logic violations or invalid domain state transitions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// Permission collision detected when multiple permissions hash to the same value
    #[error("Permission collision: {collision_count} permissions map to the same hash")]
    PermissionCollision {
        /// Number of permissions that collide
        collision_count: usize,
        /// The 64-bit hash ID that has collisions
        hash_id: u64,
        /// List of permission names that collide
        permissions: Vec<String>,
    },

    /// Invalid permission format or structure
    #[error("Invalid permission format: {permission} - {reason}")]
    InvalidPermission {
        /// The invalid permission string
        permission: String,
        /// Reason why the permission is invalid
        reason: String,
        /// Expected format or pattern
        expected_format: Option<String>,
    },

    /// Access hierarchy violation
    #[error("Access hierarchy violation: {violation_type} - {details}")]
    AccessHierarchyViolation {
        /// Type of hierarchy violation
        violation_type: String,
        /// Detailed description of the violation
        details: String,
        /// The user ID involved in the violation
        user_id: Option<String>,
        /// The resource being accessed
        resource: Option<String>,
    },

    /// Business rule violation
    #[error("Business rule violation: {rule} - {context}")]
    BusinessRuleViolation {
        /// The business rule that was violated
        rule: String,
        /// Context about the violation
        context: String,
        /// Entity ID related to the violation
        entity_id: Option<String>,
    },
}

impl DomainError {
    /// Create a permission collision error with collision details
    pub fn permission_collision(hash_id: u64, permissions: Vec<String>) -> Self {
        DomainError::PermissionCollision {
            collision_count: permissions.len(),
            hash_id,
            permissions,
        }
    }

    /// Create an invalid permission error
    pub fn invalid_permission(
        permission: impl Into<String>,
        reason: impl Into<String>,
        expected_format: Option<String>,
    ) -> Self {
        DomainError::InvalidPermission {
            permission: permission.into(),
            reason: reason.into(),
            expected_format,
        }
    }

    /// Create an access hierarchy violation error
    pub fn access_hierarchy_violation(
        violation_type: impl Into<String>,
        details: impl Into<String>,
        user_id: Option<String>,
        resource: Option<String>,
    ) -> Self {
        DomainError::AccessHierarchyViolation {
            violation_type: violation_type.into(),
            details: details.into(),
            user_id,
            resource,
        }
    }

    /// Create a business rule violation error
    pub fn business_rule_violation(
        rule: impl Into<String>,
        context: impl Into<String>,
        entity_id: Option<String>,
    ) -> Self {
        DomainError::BusinessRuleViolation {
            rule: rule.into(),
            context: context.into(),
            entity_id,
        }
    }

    /// Generate a deterministic support code based on error content
    fn generate_support_code(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            DomainError::PermissionCollision { hash_id, .. } => {
                format!("PERM-COLLISION-{}", hash_id)
            }
            DomainError::InvalidPermission { permission, .. } => {
                permission.hash(&mut hasher);
                format!("INVALID-PERM-{:X}", hasher.finish() % 10000)
            }
            DomainError::AccessHierarchyViolation { violation_type, .. } => {
                violation_type.hash(&mut hasher);
                format!("ACCESS-VIOLATION-{:X}", hasher.finish() % 10000)
            }
            DomainError::BusinessRuleViolation { rule, .. } => {
                rule.hash(&mut hasher);
                format!("BUSINESS-RULE-{:X}", hasher.finish() % 10000)
            }
        }
    }
}

impl UserFriendlyError for DomainError {
    fn user_message(&self) -> String {
        match self {
            DomainError::PermissionCollision { .. } => {
                "There's a technical issue with your account permissions. Our support team has been notified and will resolve this shortly. Please contact support if you need immediate assistance.".to_string()
            }
            DomainError::InvalidPermission { .. } => {
                "Your account permissions need to be updated. Please contact our support team who can help resolve this for you.".to_string()
            }
            DomainError::AccessHierarchyViolation { .. } => {
                "You don't have the necessary permissions to access this resource. If you believe you should have access, please contact your administrator or our support team.".to_string()
            }
            DomainError::BusinessRuleViolation { .. } => {
                "This action cannot be completed due to security or policy restrictions. Please review the requirements and try again, or contact support if you need assistance.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            DomainError::PermissionCollision {
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
            DomainError::InvalidPermission {
                permission,
                reason,
                expected_format,
            } => {
                let format_hint = expected_format
                    .as_ref()
                    .map(|f| format!(" Expected format: '{}'", f))
                    .unwrap_or_default();
                format!(
                    "Invalid permission format detected: '{}'. Validation failed: {}.{}",
                    permission, reason, format_hint
                )
            }
            DomainError::AccessHierarchyViolation {
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
            DomainError::BusinessRuleViolation {
                rule,
                context,
                entity_id,
            } => {
                let entity_context = entity_id
                    .as_ref()
                    .map(|id| format!(" [Entity: {}]", id))
                    .unwrap_or_default();
                format!(
                    "Business rule violation: '{}' failed validation - {}{}",
                    rule, context, entity_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.generate_support_code()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            DomainError::PermissionCollision { .. } => ErrorSeverity::Critical,
            DomainError::InvalidPermission { .. } => ErrorSeverity::Error,
            DomainError::AccessHierarchyViolation { .. } => ErrorSeverity::Warning,
            DomainError::BusinessRuleViolation { .. } => ErrorSeverity::Warning,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            DomainError::PermissionCollision { .. } => vec![
                "Contact our support team immediately with the reference code below".to_string(),
                "Do not attempt to retry this operation".to_string(),
                "This is a critical system issue requiring immediate administrator attention"
                    .to_string(),
            ],
            DomainError::InvalidPermission {
                expected_format, ..
            } => {
                let mut actions = vec![
                    "Contact your system administrator to review and update your permissions"
                        .to_string(),
                    "Verify you have the correct access level for your role".to_string(),
                ];
                if let Some(format) = expected_format {
                    actions.push(format!(
                        "Ensure permissions follow this format: '{}'",
                        format
                    ));
                }
                actions.push("If this problem persists, contact our support team".to_string());
                actions
            }
            DomainError::AccessHierarchyViolation { .. } => vec![
                "Check that you have the necessary permissions for this resource".to_string(),
                "Contact your administrator if you believe you should have access".to_string(),
                "Verify you are signed in with the correct account".to_string(),
                "Try refreshing your session by signing out and back in".to_string(),
            ],
            DomainError::BusinessRuleViolation { .. } => vec![
                "Review the business requirements and prerequisites for this operation".to_string(),
                "Ensure all required conditions are met before attempting this action".to_string(),
                "Contact your administrator if the requirements are unclear".to_string(),
                "Wait a moment and try again if this might be a temporary restriction".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            DomainError::PermissionCollision { .. } => false, // Critical system-level issue
            DomainError::InvalidPermission { .. } => false,   // Requires admin configuration change
            DomainError::AccessHierarchyViolation { .. } => false, // Permissions issue
            DomainError::BusinessRuleViolation { .. } => true, // User might be able to fix prerequisites
        }
    }
}
