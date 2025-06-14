use std::future::Future;

use anyhow::Result;

/// Contains the current state of a dynamic extending permission set.
///
/// This is in extend to the standard usage of the permissions when protecting your route with
/// a [Gate](crate::Gate). You can use the standard roles/groups feature and then check within your
/// route handler for specific permissions. This is particularly useful when a registered user
/// should only have access to specific categories within the same route.
pub trait DynamicPermissionService {
    /// Appends the permission to the set.
    ///
    /// The permission should be a unique string throughout the whole permission set. This method
    /// should return `Ok(())` when the permission is already present without adding it a second
    /// time.
    fn append_permission(&self, permission: &str) -> impl Future<Output = Result<()>>;

    /// Iterates through the given permission set and appends the values that are not stored yet.
    ///
    /// Does not update neither the order, nor the values of the permissions. It only checks if the
    /// permissions are in the set and if not, appends them to the end. Every other behavior would
    /// introduce a security leakage.
    fn update_permission_set(&self, permissions: Vec<String>) -> impl Future<Output = Result<()>>;

    /// Returns the number that the given permission belongs to. Returns `None` if the permission
    /// is not found in the set.
    fn permission_index(&self, permission: &str) -> impl Future<Output = Result<Option<u32>>>;

    /// Returns the permission name belonging to the index. Returns `None` if the permission
    /// is not found in the set.
    fn permission_name(&self, permission: u32) -> impl Future<Output = Result<Option<String>>>;
}
