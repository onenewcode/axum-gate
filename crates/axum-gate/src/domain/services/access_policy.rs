//! Access policy configuration for route protection
//!
//! This module defines domain objects for configuring access requirements
//! to protected resources. Access policies are pure business logic that
//! specify what roles, groups, or permissions are required for access.

use crate::domain::traits::AccessHierarchy;
use crate::domain::values::{AccessScope, Permissions};

/// Domain object representing access requirements for a protected resource.
///
/// This captures the business rules about what roles, groups, or permissions
/// are required to access a particular resource or route. Access is granted
/// if the user meets ANY of the specified requirements (OR logic).
#[derive(Debug, Clone)]
pub struct AccessPolicy<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    role_requirements: Vec<AccessScope<R>>,
    group_requirements: Vec<G>,
    permission_requirements: Permissions,
}

impl<R, G> AccessPolicy<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new access policy with no requirements (denies all access).
    ///
    /// This is the secure default - no access is granted unless explicitly
    /// configured through the builder methods.
    pub fn deny_all() -> Self {
        Self {
            role_requirements: vec![],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified role.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{AccessPolicy, Role, Group};
    ///
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);
    /// ```
    pub fn require_role(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role)],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified role or any supervisor role.
    ///
    /// This leverages the role hierarchy defined by the `AccessHierarchy` trait.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{AccessPolicy, Role, Group};
    ///
    /// // Allows Moderator role and Admin role (if Admin supervises Moderator)
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role_or_supervisor(Role::Moderator);
    /// ```
    pub fn require_role_or_supervisor(role: R) -> Self {
        Self {
            role_requirements: vec![AccessScope::new(role).allow_supervisor()],
            group_requirements: vec![],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users in the specified group.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{AccessPolicy, Group, Role};
    ///
    /// let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
    /// ```
    pub fn require_group(group: G) -> Self {
        Self {
            role_requirements: vec![],
            group_requirements: vec![group],
            permission_requirements: Permissions::new(),
        }
    }

    /// Creates a policy that allows access for users with the specified permission.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{AccessPolicy, Group, Role};
    ///
    /// let policy: AccessPolicy<Role, Group> = AccessPolicy::require_permission(42u32);
    /// ```
    pub fn require_permission<P: Into<u32>>(permission: P) -> Self {
        let mut permissions = Permissions::new();
        permissions.bitmap_mut().insert(permission.into());
        Self {
            role_requirements: vec![],
            group_requirements: vec![],
            permission_requirements: permissions,
        }
    }

    /// Adds an additional role requirement to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured roles.
    pub fn or_require_role(mut self, role: R) -> Self {
        self.role_requirements.push(AccessScope::new(role));
        self
    }

    /// Adds an additional role or supervisor requirement to this policy.
    ///
    /// Access will be granted if the user has the specified role or supervises it.
    pub fn or_require_role_or_supervisor(mut self, role: R) -> Self {
        self.role_requirements
            .push(AccessScope::new(role).allow_supervisor());
        self
    }

    /// Adds an additional group requirement to this policy.
    ///
    /// Access will be granted if the user is in ANY of the configured groups.
    pub fn or_require_group(mut self, group: G) -> Self {
        self.group_requirements.push(group);
        self
    }

    /// Adds an additional permission requirement to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured permissions.
    pub fn or_require_permission<P: Into<u32>>(mut self, permission: P) -> Self {
        self.permission_requirements
            .bitmap_mut()
            .insert(permission.into());
        self
    }

    /// Adds multiple additional permission requirements to this policy.
    ///
    /// Access will be granted if the user has ANY of the configured permissions.
    pub fn or_require_permissions<P: Into<u32>>(mut self, permissions: Vec<P>) -> Self {
        permissions.into_iter().for_each(|p| {
            self.permission_requirements.bitmap_mut().insert(p.into());
        });
        self
    }

    /// Returns the role requirements for this policy.
    pub fn role_requirements(&self) -> &[AccessScope<R>] {
        &self.role_requirements
    }

    /// Returns the group requirements for this policy.
    pub fn group_requirements(&self) -> &[G] {
        &self.group_requirements
    }

    /// Returns the permission requirements for this policy.
    pub fn permission_requirements(&self) -> &Permissions {
        &self.permission_requirements
    }

    /// Returns true if this policy has no requirements (denies all access).
    ///
    /// This is useful for validation - a policy that denies all access
    /// might indicate a configuration error.
    pub fn denies_all(&self) -> bool {
        self.role_requirements.is_empty()
            && self.group_requirements.is_empty()
            && self.permission_requirements.is_empty()
    }

    /// Returns true if this policy has at least one requirement configured.
    ///
    /// This is useful for validating that a policy is properly configured
    /// with some access requirements rather than being completely empty.
    pub fn has_requirements(&self) -> bool {
        !self.denies_all()
    }

    /// Converts this policy into the components needed by the authorization service.
    ///
    /// This is primarily used internally when bridging to the authorization service.
    pub fn into_components(self) -> (Vec<AccessScope<R>>, Vec<G>, Permissions) {
        (
            self.role_requirements,
            self.group_requirements,
            self.permission_requirements,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::{Group, Role};

    #[test]
    fn deny_all_creates_empty_policy() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::deny_all();
        assert!(policy.denies_all());
        assert!(!policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_role_creates_role_policy() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_role_or_supervisor_creates_supervisor_policy() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_role_or_supervisor(Role::Moderator);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 1);
        assert!(policy.role_requirements()[0].allow_supervisor_access);
    }

    #[test]
    fn require_group_creates_group_policy() {
        let policy: AccessPolicy<Role, Group> =
            AccessPolicy::require_group(Group::new("engineering"));
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert_eq!(policy.group_requirements().len(), 1);
        assert!(policy.permission_requirements().is_empty());
    }

    #[test]
    fn require_permission_creates_permission_policy() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_permission(42u32);
        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert!(policy.role_requirements().is_empty());
        assert!(policy.group_requirements().is_empty());
        assert!(policy.permission_requirements().iter().any(|id| id == 42));
    }

    #[test]
    fn builder_methods_add_requirements() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_role_or_supervisor(Role::Moderator)
            .or_require_group(Group::new("engineering"))
            .or_require_permission(42u32)
            .or_require_permissions(vec![1u32, 2u32, 3u32]);

        assert!(!policy.denies_all());
        assert!(policy.has_requirements());
        assert_eq!(policy.role_requirements().len(), 2);
        assert_eq!(policy.group_requirements().len(), 1);
        let perm_ids: Vec<u32> = policy.permission_requirements().iter().collect();
        assert!(perm_ids.contains(&42));
        assert!(perm_ids.contains(&1));
        assert!(perm_ids.contains(&2));
        assert!(perm_ids.contains(&3));
    }

    #[test]
    fn into_components_returns_all_requirements() {
        let policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_group(Group::new("test"))
            .or_require_permission(42u32);

        let (roles, groups, permissions) = policy.into_components();
        assert_eq!(roles.len(), 1);
        assert_eq!(groups.len(), 1);
        assert!(permissions.iter().any(|id| id == 42));
    }
}
