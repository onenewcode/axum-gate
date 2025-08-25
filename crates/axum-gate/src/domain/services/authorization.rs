use crate::domain::entities::Account;
use crate::domain::services::access_policy::AccessPolicy;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::AccessScope;

use roaring::RoaringBitmap;
use tracing::debug;

/// Domain service for authorization decisions.
///
/// This service contains pure business logic for determining whether an account
/// is authorized based on an access policy. It has no external dependencies
/// and can be used across different application contexts.
#[derive(Debug, Clone)]
pub struct AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    policy: AccessPolicy<R, G>,
}

impl<R, G> AuthorizationService<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new authorization service with the given access policy.
    pub fn new(policy: AccessPolicy<R, G>) -> Self {
        Self { policy }
    }

    /// Creates a new authorization service with the given scopes and permissions.
    ///
    /// This method is provided for backward compatibility with existing code.
    /// Consider using `new(AccessPolicy)` for new code.
    pub fn from_components(
        role_scopes: Vec<AccessScope<R>>,
        group_scope: Vec<G>,
        permissions: RoaringBitmap,
    ) -> Self {
        // Reconstruct policy from components
        let mut policy = AccessPolicy::deny_all();

        // Add role requirements
        for scope in role_scopes {
            if scope.allow_supervisor_access {
                policy = policy.or_require_role_or_supervisor(scope.role);
            } else {
                policy = policy.or_require_role(scope.role);
            }
        }

        // Add group requirements
        for group in group_scope {
            policy = policy.or_require_group(group);
        }

        // Add permission requirements
        for permission in permissions {
            policy = policy.or_require_permission(permission);
        }

        Self { policy }
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
        account.roles.iter().any(|r| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_role(r))
        })
    }

    /// Checks if the account is authorized by having a role that supervises any required role.
    pub fn authorized_by_minimum_role(&self, account: &Account<R, G>) -> bool {
        debug!("Checking if any subordinate role matches the required one.");
        account.roles.iter().any(|ur| {
            self.policy
                .role_requirements()
                .iter()
                .any(|scope| scope.grants_supervisor(ur))
        })
    }

    /// Checks if the account is authorized by being in any of the required groups.
    pub fn authorized_by_group(&self, account: &Account<R, G>) -> bool {
        account.groups.iter().any(|r| {
            self.policy
                .group_requirements()
                .iter()
                .any(|g_scope| g_scope.eq(r))
        })
    }

    /// Checks if the account is authorized by having any of the required permissions.
    pub fn authorized_by_permission(&self, account: &Account<R, G>) -> bool {
        account
            .permissions
            .iter()
            .any(|perm| self.policy.permission_requirements().contains(perm))
    }

    /// Returns true if all authorization criteria are empty (no roles, groups, or permissions configured).
    pub fn has_empty_criteria(&self) -> bool {
        self.policy.denies_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            AuthorizationService::new(AccessPolicy::deny_all());
        assert!(service.has_empty_criteria());
    }

    #[test]
    fn authorization_service_non_empty_criteria() {
        let policy = AccessPolicy::require_role(Role::Admin);
        let service: AuthorizationService<Role, Group> = AuthorizationService::new(policy);
        assert!(!service.has_empty_criteria());
    }

    #[test]
    fn authorized_by_role_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::Admin);
        let service = AuthorizationService::new(policy);

        assert!(service.authorized_by_role(&account));
    }

    #[test]
    fn authorized_by_role_not_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User);
        let service = AuthorizationService::new(policy);

        assert!(!service.authorized_by_role(&account));
    }

    #[test]
    fn authorized_by_group_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_group(Group::new("engineering"));
        let service = AuthorizationService::new(policy);

        assert!(service.authorized_by_group(&account));
    }

    #[test]
    fn authorized_by_group_not_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_group(Group::new("sales"));
        let service = AuthorizationService::new(policy);

        assert!(!service.authorized_by_group(&account));
    }

    #[test]
    fn authorized_by_permission_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_permission(1u32); // Account has permission 1
        let service = AuthorizationService::new(policy);

        assert!(service.authorized_by_permission(&account));
    }

    #[test]
    fn authorized_by_permission_not_matching() {
        let account = create_test_account();
        let policy = AccessPolicy::require_permission(10u32); // Account doesn't have permission 10
        let service = AuthorizationService::new(policy);

        assert!(!service.authorized_by_permission(&account));
    }

    #[test]
    fn is_authorized_returns_true_when_any_criteria_match() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User) // Won't match
            .or_require_group(Group::new("engineering")); // Will match
        let service = AuthorizationService::new(policy);

        assert!(service.is_authorized(&account));
    }

    #[test]
    fn is_authorized_returns_false_when_no_criteria_match() {
        let account = create_test_account();
        let policy = AccessPolicy::require_role(Role::User) // Won't match
            .or_require_group(Group::new("sales")); // Won't match
        let service = AuthorizationService::new(policy);

        assert!(!service.is_authorized(&account));
    }
}
