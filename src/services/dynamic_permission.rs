use std::future::Future;

use anyhow::Result;

/// Provides the implementor with the possibility to act as dynamic permission set.
///
/// In extend to the static roles and groups feature of `axum-gate`, it is also possible to use a
/// dynamic permission set for fine-grained resource control. This is done by using the
/// [DynamicPermissionService] within your actual route handler. Particularly useful when
/// a registered user should only have access to specific resources within the same route and
/// your resources change over time.
///
/// However, keep in mind that the [PermissionSet](crate::PermissionSet) is stored in the cookie
/// as well and **has a maximum amount of `u32` permissions**.
///
/// It is also applicable within a distributed system. See the pre-defined
/// [route_handler](crate::route_handlers#dynamic-permission-set) for more information.
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
    fn extend_permission_set(&self, permissions: Vec<String>) -> impl Future<Output = Result<()>>;

    /// Returns the number that the given permission belongs to. Returns `None` if the permission
    /// is not found in the set.
    fn permission_index(&self, permission: &str) -> impl Future<Output = Result<Option<u32>>>;

    /// Returns the permission name belonging to the index. Returns `None` if the permission
    /// is not found in the set.
    fn permission_name(&self, permission: u32) -> impl Future<Output = Result<Option<String>>>;
}
