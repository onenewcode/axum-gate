//! Permissions value object for managing user permissions.
//!
//! This module provides a clean abstraction over permission management,
//! hiding the underlying RoaringTreemap implementation and providing
//! an intuitive API for working with permissions.

use crate::domain::values::PermissionId;

use std::fmt;

use roaring::RoaringTreemap;
use serde::{Deserialize, Serialize};

/// A collection of permissions that provides a clean API for permission management.
///
/// This struct abstracts away the underlying RoaringTreemap implementation,
/// providing a more intuitive and flexible interface for working with permissions.
/// It maintains all the performance benefits of RoaringTreemap while offering
/// better developer experience and future flexibility.
///
/// # Examples
///
/// ```rust
/// use axum_gate::Permissions;
///
/// // Create and populate permissions
/// let mut permissions = Permissions::new();
/// permissions
///     .grant("read:profile")
///     .grant("write:profile")
///     .grant("delete:profile");
///
/// // Check individual permissions
/// assert!(permissions.has("read:profile"));
/// assert!(!permissions.has("admin:users"));
///
/// // Check multiple permissions
/// assert!(permissions.has_all(["read:profile", "write:profile"]));
/// assert!(permissions.has_any(["read:profile", "admin:users"]));
/// ```
///
/// # Builder Pattern
///
/// ```rust
/// use axum_gate::Permissions;
///
/// let permissions = Permissions::new()
///     .with("read:api")
///     .with("write:api")
///     .build();
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Permissions {
    bitmap: RoaringTreemap,
}

impl Permissions {
    /// Creates a new empty permission set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::new();
    /// assert!(permissions.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            bitmap: RoaringTreemap::new(),
        }
    }

    /// Creates a permission set from an iterator of permission names.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::from_iter([
    ///     "read:profile",
    ///     "write:profile",
    ///     "read:posts"
    /// ]);
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has("write:profile"));
    /// assert!(permissions.has("read:posts"));
    /// ```
    pub fn from_iter<I, P>(permissions: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        let mut perms = Self::new();
        for permission in permissions {
            perms.grant(permission);
        }
        perms
    }

    /// Grants a permission to this permission set.
    ///
    /// Returns a mutable reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let mut permissions = Permissions::new();
    /// permissions
    ///     .grant("read:profile")
    ///     .grant(PermissionId::from("write:profile"));
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has(PermissionId::from("write:profile")));
    /// ```
    pub fn grant<P>(&mut self, permission: P) -> &mut Self
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.insert(permission_id.as_u64());
        self
    }

    /// Revokes a permission from this permission set.
    ///
    /// Returns a mutable reference to self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let mut permissions = Permissions::from_iter(["read:profile", "write:profile"]);
    /// permissions.revoke(PermissionId::from("write:profile"));
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(!permissions.has("write:profile"));
    /// ```
    pub fn revoke<P>(&mut self, permission: P) -> &mut Self
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.remove(permission_id.as_u64());
        self
    }

    /// Checks if a specific permission is granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let permissions = Permissions::from_iter(["read:profile"]);
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has(PermissionId::from("read:profile")));
    /// assert!(!permissions.has("write:profile"));
    /// ```
    pub fn has<P>(&self, permission: P) -> bool
    where
        P: Into<PermissionId>,
    {
        let permission_id = permission.into();
        self.bitmap.contains(permission_id.as_u64())
    }

    /// Checks if all of the specified permissions are granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let permissions = Permissions::from_iter([
    ///     "read:profile",
    ///     "write:profile",
    ///     "read:posts"
    /// ]);
    ///
    /// assert!(permissions.has_all(["read:profile", "write:profile"]));
    /// assert!(permissions.has_all([PermissionId::from("read:profile")]));
    /// assert!(!permissions.has_all(["read:profile", "admin:users"]));
    /// ```
    pub fn has_all<I, P>(&self, permissions: I) -> bool
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        permissions.into_iter().all(|p| self.has(p))
    }

    /// Checks if any of the specified permissions are granted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let permissions = Permissions::from_iter(["read:profile"]);
    ///
    /// assert!(permissions.has_any(["read:profile", "write:profile"]));
    /// assert!(permissions.has_any([PermissionId::from("read:profile")]));
    /// assert!(!permissions.has_any(["write:profile", "admin:users"]));
    /// ```
    pub fn has_any<I, P>(&self, permissions: I) -> bool
    where
        I: IntoIterator<Item = P>,
        P: Into<PermissionId>,
    {
        permissions.into_iter().any(|p| self.has(p))
    }

    /// Returns the number of permissions in this set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::from_iter(["read:profile", "write:profile"]);
    /// assert_eq!(permissions.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.bitmap.len() as usize
    }

    /// Returns `true` if the permission set contains no permissions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::new();
    /// assert!(permissions.is_empty());
    ///
    /// let mut permissions = Permissions::new();
    /// permissions.grant("read:profile");
    /// assert!(!permissions.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.bitmap.is_empty()
    }

    /// Removes all permissions from this set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let mut permissions = Permissions::from_iter(["read:profile", "write:profile"]);
    /// assert!(!permissions.is_empty());
    ///
    /// permissions.clear();
    /// assert!(permissions.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.bitmap.clear();
    }

    /// Computes the union of this permission set with another.
    ///
    /// This grants all permissions that exist in either set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let mut permissions1 = Permissions::from_iter(["read:profile"]);
    /// let permissions2 = Permissions::from_iter(["write:profile"]);
    ///
    /// permissions1.union(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(permissions1.has("write:profile"));
    /// ```
    pub fn union(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap |= &other.bitmap;
        self
    }

    /// Computes the intersection of this permission set with another.
    ///
    /// This keeps only permissions that exist in both sets.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let mut permissions1 = Permissions::from_iter(["read:profile", "write:profile"]);
    /// let permissions2 = Permissions::from_iter(["read:profile", "admin:users"]);
    ///
    /// permissions1.intersection(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(!permissions1.has("write:profile"));
    /// assert!(!permissions1.has("admin:users"));
    /// ```
    pub fn intersection(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap &= &other.bitmap;
        self
    }

    /// Computes the difference of this permission set with another.
    ///
    /// This removes all permissions that exist in the other set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let mut permissions1 = Permissions::from_iter(["read:profile", "write:profile"]);
    /// let permissions2 = Permissions::from_iter(["write:profile"]);
    ///
    /// permissions1.difference(&permissions2);
    ///
    /// assert!(permissions1.has("read:profile"));
    /// assert!(!permissions1.has("write:profile"));
    /// ```
    pub fn difference(&mut self, other: &Permissions) -> &mut Self {
        self.bitmap -= &other.bitmap;
        self
    }

    /// Builder method for granting a permission (immutable version).
    ///
    /// This is useful for building permissions in a functional style.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::{Permissions, PermissionId};
    ///
    /// let permissions = Permissions::new()
    ///     .with("read:profile")
    ///     .with(PermissionId::from("write:profile"))
    ///     .build();
    ///
    /// assert!(permissions.has("read:profile"));
    /// assert!(permissions.has("write:profile"));
    /// ```
    pub fn with<P>(mut self, permission: P) -> Self
    where
        P: Into<PermissionId>,
    {
        self.grant(permission);
        self
    }

    /// Finalizes the builder pattern (for aesthetic purposes).
    ///
    /// This method does nothing but return self, but provides a nice
    /// conclusion to the builder pattern.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::new()
    ///     .with("read:profile")
    ///     .with("write:profile")
    ///     .build();
    /// ```
    pub fn build(self) -> Self {
        self
    }

    /// Returns an iterator over the raw permission IDs.
    ///
    /// This is primarily for advanced use cases where you need to work
    /// with the underlying bitmap data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::Permissions;
    ///
    /// let permissions = Permissions::from_iter(["read:profile", "write:profile"]);
    /// let ids: Vec<u64> = permissions.iter().collect();
    /// assert_eq!(ids.len(), 2);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.bitmap.iter()
    }

    /// Internal method to access the underlying bitmap for testing.
    ///
    /// This method is intended for internal use only and should not be used
    /// in production code. It provides direct access to the underlying
    /// RoaringTreemap for testing purposes.
    #[doc(hidden)]
    pub fn bitmap_mut(&mut self) -> &mut roaring::RoaringTreemap {
        &mut self.bitmap
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permissions({})", self.len())
    }
}

impl From<roaring::RoaringTreemap> for Permissions {
    fn from(bitmap: roaring::RoaringTreemap) -> Self {
        Self { bitmap }
    }
}

impl From<Permissions> for roaring::RoaringTreemap {
    fn from(permissions: Permissions) -> Self {
        permissions.bitmap
    }
}

impl AsRef<roaring::RoaringTreemap> for Permissions {
    fn as_ref(&self) -> &roaring::RoaringTreemap {
        &self.bitmap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_permissions_is_empty() {
        let permissions = Permissions::new();
        assert!(permissions.is_empty());
        assert_eq!(permissions.len(), 0);
    }

    #[test]
    fn grant_and_has_permission() {
        let mut permissions = Permissions::new();
        permissions.grant("read:profile");

        assert!(permissions.has("read:profile"));
        assert!(!permissions.has("write:profile"));
        assert_eq!(permissions.len(), 1);
        assert!(!permissions.is_empty());
    }

    #[test]
    fn grant_chaining() {
        let mut permissions = Permissions::new();
        permissions
            .grant("read:profile")
            .grant("write:profile")
            .grant("delete:profile");

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert!(permissions.has("delete:profile"));
        assert_eq!(permissions.len(), 3);
    }

    #[test]
    fn revoke_permission() {
        let mut permissions = Permissions::from_iter(["read:profile", "write:profile"]);
        permissions.revoke("write:profile");

        assert!(permissions.has("read:profile"));
        assert!(!permissions.has("write:profile"));
        assert_eq!(permissions.len(), 1);
    }

    #[test]
    fn has_all_permissions() {
        let permissions = Permissions::from_iter(["read:profile", "write:profile", "read:posts"]);

        assert!(permissions.has_all(["read:profile", "write:profile"]));
        assert!(permissions.has_all(["read:profile"]));
        assert!(!permissions.has_all(["read:profile", "admin:users"]));
        assert!(permissions.has_all(Vec::<&str>::new())); // empty set
    }

    #[test]
    fn has_any_permission() {
        let permissions = Permissions::from_iter(["read:profile"]);

        assert!(permissions.has_any(["read:profile", "write:profile"]));
        assert!(permissions.has_any(["write:profile", "read:profile"]));
        assert!(!permissions.has_any(["write:profile", "admin:users"]));
        assert!(!permissions.has_any(Vec::<&str>::new())); // empty set
    }

    #[test]
    fn clear_permissions() {
        let mut permissions = Permissions::from_iter(["read:profile", "write:profile"]);
        assert!(!permissions.is_empty());

        permissions.clear();
        assert!(permissions.is_empty());
        assert_eq!(permissions.len(), 0);
    }

    #[test]
    fn union_permissions() {
        let mut permissions1 = Permissions::from_iter(["read:profile"]);
        let permissions2 = Permissions::from_iter(["write:profile", "read:posts"]);

        permissions1.union(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(permissions1.has("write:profile"));
        assert!(permissions1.has("read:posts"));
        assert_eq!(permissions1.len(), 3);
    }

    #[test]
    fn intersection_permissions() {
        let mut permissions1 = Permissions::from_iter(["read:profile", "write:profile"]);
        let permissions2 = Permissions::from_iter(["read:profile", "admin:users"]);

        permissions1.intersection(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(!permissions1.has("write:profile"));
        assert!(!permissions1.has("admin:users"));
        assert_eq!(permissions1.len(), 1);
    }

    #[test]
    fn difference_permissions() {
        let mut permissions1 = Permissions::from_iter(["read:profile", "write:profile"]);
        let permissions2 = Permissions::from_iter(["write:profile"]);

        permissions1.difference(&permissions2);

        assert!(permissions1.has("read:profile"));
        assert!(!permissions1.has("write:profile"));
        assert_eq!(permissions1.len(), 1);
    }

    #[test]
    fn builder_pattern() {
        let permissions = Permissions::new()
            .with("read:profile")
            .with("write:profile")
            .build();

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert_eq!(permissions.len(), 2);
    }

    #[test]
    fn from_iter() {
        let permissions = Permissions::from_iter(["read:profile", "write:profile", "read:posts"]);

        assert!(permissions.has("read:profile"));
        assert!(permissions.has("write:profile"));
        assert!(permissions.has("read:posts"));
        assert_eq!(permissions.len(), 3);
    }

    #[test]
    fn permissions_are_deterministic() {
        let permissions1 = Permissions::from_iter(["read:profile"]);
        let permissions2 = Permissions::from_iter(["read:profile"]);

        assert_eq!(permissions1, permissions2);
        assert!(permissions1.has("read:profile"));
        assert!(permissions2.has("read:profile"));
    }

    #[test]
    fn display_implementation() {
        let permissions = Permissions::from_iter(["read:profile", "write:profile"]);
        let display = format!("{}", permissions);
        assert_eq!(display, "Permissions(2)");
    }
}
