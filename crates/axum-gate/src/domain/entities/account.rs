use crate::domain::traits::AccessHierarchy;
#[cfg(feature = "storage-seaorm")]
use crate::domain::traits::CommaSeparatedValue;
use crate::domain::values::{PermissionId, Permissions};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An account contains authorization information about a user.
///
/// Accounts store user identification, roles, groups, and permissions. They are the
/// core entity for authorization decisions in axum-gate.
///
/// # Creating Accounts
///
/// ```rust
/// use axum_gate::{Account, Role, Group, Permissions};
///
/// // Create a basic account
/// let account = Account::new("user123", &[Role::User], &[Group::new("staff")]);
///
/// // Create account with permissions
/// let permissions = Permissions::from_iter(["read:profile", "write:profile"]);
///
/// let account = Account::<Role, Group>::new("admin@example.com", &[Role::Admin], &[])
///     .with_permissions(permissions);
/// ```
///
/// # Working with Permissions
///
/// ```rust
/// # use axum_gate::{Account, Role, Group, PermissionId};
/// # let mut account = Account::<Role, Group>::new("user", &[], &[]);
/// // Grant permissions
/// account.grant_permission("read:api");
/// account.grant_permission(PermissionId::from("write:api"));
///
/// // Check permissions directly
/// if account.permissions.has("read:api") {
///     println!("User can read API");
/// }
///
/// // Revoke permissions
/// account.revoke_permission("write:api");
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct Account<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// The unique identifier of the account generated during registration.
    ///
    /// This UUID links the account to its corresponding authentication secret
    /// in the secret repository. The separation of account data from secrets
    /// enhances security by allowing different storage backends and access controls.
    pub account_id: Uuid,
    /// The user identifier for this account (e.g., email, username).
    ///
    /// This should be unique within your application and is typically what users
    /// provide during login. It's used to look up accounts in the repository.
    pub user_id: String,
    /// Roles assigned to this account.
    ///
    /// Roles determine what actions a user can perform. If your roles implement
    /// `AccessHierarchy`, supervisor roles automatically inherit subordinate permissions.
    pub roles: Vec<R>,
    /// Groups this account belongs to.
    ///
    /// Groups provide another dimension of access control, allowing you to grant
    /// permissions based on team membership, department, or other organizational units.
    pub groups: Vec<G>,
    /// Custom permissions granted to this account.
    ///
    /// Uses a compressed bitmap for efficient storage and fast permission checks.
    /// Permissions are automatically available when referenced by name using
    /// deterministic hashing - no coordination between nodes required.
    pub permissions: Permissions,
}

impl<R, G> Account<R, G>
where
    R: AccessHierarchy + Eq + Clone,
    G: Eq + Clone,
{
    /// Creates a new account with the specified user ID, roles, and groups.
    ///
    /// A random UUID is automatically generated for the account ID. The account
    /// starts with no permissions - use `with_permissions()` or `grant_permission()`
    /// to add them.
    ///
    /// # Arguments
    /// * `user_id` - Unique identifier for the user (e.g., email or username)
    /// * `roles` - Roles to assign to this account
    /// * `groups` - Groups this account should belong to
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{Account, Role, Group};
    ///
    /// let account = Account::new(
    ///     "user@example.com",
    ///     &[Role::User, Role::Reporter],
    ///     &[Group::new("engineering"), Group::new("backend-team")]
    /// );
    /// ```
    pub fn new(user_id: &str, roles: &[R], groups: &[G]) -> Self {
        let roles = roles.to_vec();
        let groups = groups.to_vec();
        Self {
            account_id: Uuid::now_v7(),
            user_id: user_id.to_owned(),
            groups,
            roles,
            permissions: Permissions::new(),
        }
    }

    /// Creates a new account with the specified account ID.
    ///
    /// This constructor is primarily used internally when loading accounts from
    /// repositories. Most applications should use `new()` which generates a random ID.
    ///
    /// # Arguments
    /// * `account_id` - The UUID to use for this account
    /// * `user_id` - Unique identifier for the user
    /// * `roles` - Roles to assign to this account
    /// * `groups` - Groups this account should belong to
    #[cfg(feature = "storage-seaorm")]
    pub(crate) fn new_with_account_id(
        account_id: &Uuid,
        user_id: &str,
        roles: &[R],
        groups: &[G],
    ) -> Self {
        let roles = roles.to_vec();
        let groups = groups.to_vec();
        Self {
            account_id: account_id.to_owned(),
            user_id: user_id.to_owned(),
            groups,
            roles,
            permissions: Permissions::new(),
        }
    }

    /// Consumes this account and returns it with the specified permissions.
    ///
    /// This is useful when building accounts with specific permission sets.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{Account, Role, Group, Permissions};
    ///
    /// // Create permissions
    /// let permissions = Permissions::from_iter(["read:profile", "write:profile"]);
    ///
    /// let account = Account::<Role, Group>::new("user@example.com", &[Role::User], &[])
    ///     .with_permissions(permissions);
    /// ```
    pub fn with_permissions(self, permissions: Permissions) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Grants a permission to this account.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{Account, Role, Group, PermissionId};
    ///
    /// let mut account = Account::<Role, Group>::new("user", &[], &[]);
    /// account.grant_permission("read:profile");
    /// account.grant_permission(PermissionId::from("write:profile"));
    /// ```
    pub fn grant_permission<P>(&mut self, permission: P)
    where
        P: Into<PermissionId>,
    {
        self.permissions.grant(permission);
    }

    /// Revokes a permission from this account.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::{Account, Role, Group, PermissionId};
    ///
    /// let mut account = Account::<Role, Group>::new("user", &[], &[]);
    /// account.grant_permission("write:profile");
    /// account.revoke_permission(PermissionId::from("write:profile"));
    /// ```
    pub fn revoke_permission<P>(&mut self, permission: P)
    where
        P: Into<PermissionId>,
    {
        self.permissions.revoke(permission);
    }
}

#[cfg(feature = "storage-seaorm")]
impl<R, G> TryFrom<crate::infrastructure::repositories::sea_orm::models::account::Model>
    for Account<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    Vec<R>: CommaSeparatedValue,
    G: Eq + Clone,
    Vec<G>: CommaSeparatedValue,
{
    type Error = String;

    fn try_from(
        value: crate::infrastructure::repositories::sea_orm::models::account::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self::new_with_account_id(
            &value.account_id,
            &value.user_id,
            &Vec::<R>::from_csv(&value.roles)?,
            &Vec::<G>::from_csv(&value.groups)?,
        ))
    }
}
