//! Legacy dynamic permission service - deprecated in favor of zero-sync architecture.
//!
//! This module provides backward compatibility for the old dynamic permission system.
//! New code should use the zero-synchronization permission system in the `permissions` module
//! which eliminates the need for dynamic permission sets entirely.

use anyhow::Result;
use std::future::Future;

/// Legacy trait for dynamic permission management.
///
/// **DEPRECATED**: This trait is maintained for backward compatibility only.
/// The new zero-synchronization permission system in [`crate::permissions`] eliminates
/// the need for dynamic permission sets by using deterministic hashing.
///
/// ## Migration Guide
///
/// Instead of using `DynamicPermissionService`, use the new permission system:
///
/// ```
/// use axum_gate::{PermissionChecker, PermissionId};
/// use roaring::RoaringBitmap;
///
/// let mut user_permissions = RoaringBitmap::new();
///
/// // Old way (deprecated):
/// // let index = permission_service.permission_index("read:file").await?;
/// // user_permissions.insert(index);
///
/// // New way:
/// PermissionChecker::grant_permission(&mut user_permissions, "read:file");
/// let has_access = PermissionChecker::has_permission(&user_permissions, "read:file");
/// ```
///
/// ## Benefits of Migration
///
/// - **Zero synchronization**: No need to coordinate permission sets between nodes
/// - **Better performance**: No async operations for permission lookups
/// - **Distributed-friendly**: Works seamlessly across multiple nodes
/// - **Collision-resistant**: Uses SHA-256 for stable permission IDs
#[deprecated(
    since = "0.5.0",
    note = "Use the zero-synchronization permission system in axum_gate::permissions instead"
)]
pub trait DynamicPermissionService {
    /// Appends the permission to the set.
    ///
    /// **DEPRECATED**: In the new system, permissions don't need to be "appended" to any set.
    /// Permission IDs are computed deterministically from names.
    ///
    /// Migration: Remove calls to this method. Permissions are automatically available
    /// when you reference them by name.
    fn append_permission(&self, permission: &str) -> impl Future<Output = Result<()>>;

    /// Iterates through the given permission set and appends the values that are not stored yet.
    ///
    /// **DEPRECATED**: In the new system, permission sets don't need to be synchronized.
    ///
    /// Migration: Remove calls to this method. All nodes automatically understand
    /// all permission names.
    fn extend_permission_set(&self, permissions: Vec<String>) -> impl Future<Output = Result<()>>;

    /// Returns the number that the given permission belongs to.
    ///
    /// **DEPRECATED**: Use `PermissionId::from_name(permission).as_u32()` instead.
    ///
    /// Migration:
    /// ```
    /// use axum_gate::PermissionId;
    ///
    /// // Old:
    /// // let id = service.permission_index("read:file").await?.unwrap();
    ///
    /// // New:
    /// let id = PermissionId::from_name("read:file").as_u32();
    /// ```
    fn permission_index(&self, permission: &str) -> impl Future<Output = Result<Option<u32>>>;

    /// Returns the permission name belonging to the index.
    ///
    /// **DEPRECATED**: The new system doesn't provide reverse lookup as it's not needed
    /// for authorization. If you need this for debugging, maintain your own mapping.
    ///
    /// Migration: Store permission names separately if reverse lookup is needed for
    /// debugging or audit purposes.
    fn permission_name(&self, permission: u32) -> impl Future<Output = Result<Option<String>>>;
}

/// Legacy permission set implementation.
///
/// **DEPRECATED**: This struct is maintained for backward compatibility only.
/// Use the new zero-synchronization permission system instead.
///
/// ## Migration Example
///
/// ```
/// use axum_gate::PermissionChecker;
/// use roaring::RoaringBitmap;
///
/// let mut user_permissions = RoaringBitmap::new();
///
/// // Old code:
/// // let permission_set = PermissionSet::new(vec![
/// //     "read:file".to_string(),
/// //     "write:file".to_string(),
/// // ]);
/// // let index = permission_set.permission_index("read:file").await?.unwrap();
/// // user_permissions.insert(index);
///
/// // New code:
/// PermissionChecker::grant_permission(&mut user_permissions, "read:file");
/// ```
#[deprecated(
    since = "0.5.0",
    note = "Use PermissionChecker from axum_gate::permissions instead"
)]
pub struct LegacyPermissionSet {
    // Empty - this is just a compatibility shim
}

#[allow(deprecated)]
impl LegacyPermissionSet {
    /// Creates a new legacy permission set.
    ///
    /// **DEPRECATED**: No longer needed in the new architecture.
    pub fn new(_permissions: Vec<String>) -> Self {
        Self {}
    }
}

#[allow(deprecated)]
impl DynamicPermissionService for LegacyPermissionSet {
    async fn append_permission(&self, _permission: &str) -> Result<()> {
        // No-op in new architecture - permissions are always available
        Ok(())
    }

    async fn extend_permission_set(&self, _permissions: Vec<String>) -> Result<()> {
        // No-op in new architecture - permissions are always available
        Ok(())
    }

    async fn permission_index(&self, permission: &str) -> Result<Option<u32>> {
        // Use the new deterministic system
        Ok(Some(
            crate::permissions::PermissionId::from_name(permission).as_u32(),
        ))
    }

    async fn permission_name(&self, _permission: u32) -> Result<Option<String>> {
        // Reverse lookup not supported in new architecture
        Ok(None)
    }
}

/// Re-export for backward compatibility.
#[deprecated(
    since = "0.5.0",
    note = "Use PermissionChecker from axum_gate::permissions instead"
)]
pub use LegacyPermissionSet as PermissionSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(deprecated)]
    async fn legacy_compatibility() {
        let permission_set =
            LegacyPermissionSet::new(vec!["read:file".to_string(), "write:file".to_string()]);

        // Should work for backward compatibility
        let index = permission_set.permission_index("read:file").await.unwrap();
        assert!(index.is_some());

        // Should be deterministic
        let index2 = permission_set.permission_index("read:file").await.unwrap();
        assert_eq!(index, index2);
    }
}
