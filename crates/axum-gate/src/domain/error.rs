//! Domain layer error types for business logic violations.
//!
//! This module contains error types that represent violations of business rules
//! and domain logic. These errors are independent of external systems and
//! represent pure domain concerns.

use thiserror::Error;

/// Domain layer errors representing business rule violations and domain logic failures.
///
/// These errors are independent of external systems and represent pure business
/// logic violations or invalid domain state transitions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// Permission collision detected
    #[error("Permission collision: {collision_count} permissions map to the same hash")]
    PermissionCollision {
        /// Number of permissions that collide
        collision_count: usize,
        /// The 64-bit hash ID that has collisions
        hash_id: u64,
        /// List of permission names that collide
        permissions: Vec<String>,
    },
}

/// Permission collision information for domain errors
#[derive(Debug, Clone)]
pub struct PermissionCollision {
    /// The 64-bit hash ID that has collisions
    pub id: u64,
    /// List of permission names that collide
    pub permissions: Vec<String>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_collision_constructor() {
        let permissions = vec!["read:file".to_string(), "write:file".to_string()];
        let error = DomainError::permission_collision(123u64, permissions.clone());

        match error {
            DomainError::PermissionCollision {
                collision_count,
                hash_id,
                permissions: perms,
            } => {
                assert_eq!(collision_count, 2);
                assert_eq!(hash_id, 123);
                assert_eq!(perms, permissions);
            }
        }
    }

    #[test]
    fn error_display() {
        let error = DomainError::permission_collision(123u64, vec!["test".to_string()]);
        let display = format!("{}", error);
        assert!(display.contains("Permission collision"));
    }
}
