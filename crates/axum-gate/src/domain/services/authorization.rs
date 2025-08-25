use crate::domain::entities::Account;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::AccessScope;

use roaring::RoaringBitmap;
use tracing::debug;

/// Domain service for authorization decisions.
///
/// This service contains pure business logic for determining whether an account
/// is authorized based on roles, groups, and permissions. It has no external
/// dependencies and can be used across different application contexts.
#[derive(Debug, Clone)]
pub struct AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    role_scopes: Vec<AccessScope<R>>,
    group_scope: Vec<G>,
    permissions: RoaringBitmap,
}

impl<R, G> AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new authorization service with the given scopes and permissions.
    pub fn new(
        role_scopes: Vec<AccessScope<R>>,
        group_scope: Vec<G>,
        permissions: RoaringBitmap,
    ) -> Self {
        Self {
            role_scopes,
            group_scope,
            permissions,
        }
    }

    /// Determines if the account is authorized based on any of the configured criteria.
    ///
    /// Returns `true` if the account matches any of:
    /// - Required permissions
    /// - Required groups
    /// - Required roles
    /// - Required minimum roles (supervisor access)
    pub fn is_authorized(&self, account: &Account<R, G>) -> bool {
        self.authorized_by_permission(account)
            || self.authorized_by_group(account)
            || self.authorized_by_role(account)
            || self.authorized_by_minimum_role(account)
    }

    /// Checks if the account is authorized by having any of the required roles.
    pub fn authorized_by_role(&self, account: &Account<R, G>) -> bool {
        account
            .roles
            .iter()
            .any(|r| self.role_scopes.iter().any(|scope| scope.grants_role(r)))
    }

    /// Checks if the account is authorized by having a role that supervises any required role.
    pub fn authorized_by_minimum_role(&self, account: &Account<R, G>) -> bool {
        debug!("Checking if any subordinate role matches the required one.");
        account.roles.iter().any(|ur| {
            self.role_scopes
                .iter()
                .any(|scope| scope.grants_supervisor(ur))
        })
    }

    /// Checks if the account is authorized by being in any of the required groups.
    pub fn authorized_by_group(&self, account: &Account<R, G>) -> bool {
        account
            .groups
            .iter()
            .any(|r| self.group_scope.iter().any(|g_scope| g_scope.eq(r)))
    }

    /// Checks if the account is authorized by having any of the required permissions.
    pub fn authorized_by_permission(&self, account: &Account<R, G>) -> bool {
        account
            .permissions
            .iter()
            .any(|perm| self.permissions.contains(perm))
    }

    /// Returns true if all authorization criteria are empty (no roles, groups, or permissions configured).
    pub fn has_empty_criteria(&self) -> bool {
        self.group_scope.is_empty() && self.role_scopes.is_empty() && self.permissions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::AccessScope;
    use crate::{Group, Role};

    fn create_test_account() -> Account<Role, Group> {
        use roaring::RoaringBitmap;
        use uuid::Uuid;

        let mut permissions = RoaringBitmap::new();
        permissions.insert(1);
        permissions.insert(5);

        Account {
            account_id: Uuid::new_v4(),
            user_id: "test_user".to_string(),
            roles: vec![Role::Admin],
            groups: vec![Group::new("engineering")],
            permissions,
        }
    }

    #[test]
    fn authorization_service_empty_criteria() {
        let service: AuthorizationService<Role, Group> =
            AuthorizationService::new(vec![], vec![], RoaringBitmap::new());
        assert!(service.has_empty_criteria());
    }

    #[test]
    fn authorization_service_non_empty_criteria() {
        let role_scopes = vec![AccessScope::new(Role::Admin)];
        let service: AuthorizationService<Role, Group> =
            AuthorizationService::new(role_scopes, vec![], RoaringBitmap::new());
        assert!(!service.has_empty_criteria());
    }

    #[test]
    fn authorized_by_role_matching() {
        let account = create_test_account();
        let role_scopes = vec![AccessScope::new(Role::Admin)];
        let service = AuthorizationService::new(role_scopes, vec![], RoaringBitmap::new());

        assert!(service.authorized_by_role(&account));
    }

    #[test]
    fn authorized_by_role_not_matching() {
        let account = create_test_account();
        let role_scopes = vec![AccessScope::new(Role::User)];
        let service = AuthorizationService::new(role_scopes, vec![], RoaringBitmap::new());

        assert!(!service.authorized_by_role(&account));
    }

    #[test]
    fn authorized_by_group_matching() {
        let account = create_test_account();
        let group_scope = vec![Group::new("engineering")];
        let service = AuthorizationService::new(vec![], group_scope, RoaringBitmap::new());

        assert!(service.authorized_by_group(&account));
    }

    #[test]
    fn authorized_by_group_not_matching() {
        let account = create_test_account();
        let group_scope = vec![Group::new("sales")];
        let service = AuthorizationService::new(vec![], group_scope, RoaringBitmap::new());

        assert!(!service.authorized_by_group(&account));
    }

    #[test]
    fn authorized_by_permission_matching() {
        let account = create_test_account();
        let mut permissions = RoaringBitmap::new();
        permissions.insert(1); // Account has permission 1
        let service = AuthorizationService::new(vec![], vec![], permissions);

        assert!(service.authorized_by_permission(&account));
    }

    #[test]
    fn authorized_by_permission_not_matching() {
        let account = create_test_account();
        let mut permissions = RoaringBitmap::new();
        permissions.insert(10); // Account doesn't have permission 10
        let service = AuthorizationService::new(vec![], vec![], permissions);

        assert!(!service.authorized_by_permission(&account));
    }

    #[test]
    fn is_authorized_returns_true_when_any_criteria_match() {
        let account = create_test_account();
        let role_scopes = vec![AccessScope::new(Role::User)]; // Won't match
        let group_scope = vec![Group::new("engineering")]; // Will match
        let permissions = RoaringBitmap::new(); // Won't match
        let service = AuthorizationService::new(role_scopes, group_scope, permissions);

        assert!(service.is_authorized(&account));
    }

    #[test]
    fn is_authorized_returns_false_when_no_criteria_match() {
        let account = create_test_account();
        let role_scopes = vec![AccessScope::new(Role::User)]; // Won't match
        let group_scope = vec![Group::new("sales")]; // Won't match
        let permissions = RoaringBitmap::new(); // Won't match
        let service = AuthorizationService::new(role_scopes, group_scope, permissions);

        assert!(!service.is_authorized(&account));
    }
}
