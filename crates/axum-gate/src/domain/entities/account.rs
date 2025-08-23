use crate::domain::traits::AccessHierarchy;
#[cfg(feature = "storage-seaorm")]
use crate::domain::traits::CommaSeparatedValue;

use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An account contains authorization information about a user.
#[derive(Serialize, Deserialize, Clone)]
pub struct Account<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// The unique identifier of the account which has been generated on registration.
    ///
    /// This identifier is the loose connection to the [Secret](crate::secrets::Secret) in
    /// a [SecretRepositoryService](crate::services::SecretRepositoryService).
    pub account_id: Uuid,
    /// The user id for this account. This should be unique within your application.
    pub user_id: String,
    /// Roles of this account.
    pub roles: Vec<R>,
    /// Groups the account belongs to.
    pub groups: Vec<G>,
    /// Custom permissions that can be added to an account.
    pub permissions: RoaringBitmap,
}

impl<R, G> Account<R, G>
where
    R: AccessHierarchy + Eq + Clone,
    G: Eq + Clone,
{
    /// Creates a new account with the username, groups and roles. An account id is randomly
    /// generated.
    pub fn new(user_id: &str, roles: &[R], groups: &[G]) -> Self {
        let roles = roles.to_vec();
        let groups = groups.to_vec();
        Self {
            account_id: Uuid::now_v7(),
            user_id: user_id.to_owned(),
            groups,
            roles,
            permissions: RoaringBitmap::new(),
        }
    }

    /// Creates a new account with the given `account_id`.
    ///
    /// This is only used to transform the result of a repository query into the [Account] model.
    pub fn new_with_account_id(
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
            permissions: RoaringBitmap::new(),
        }
    }

    /// Consumes `self` and sets the given permission set.
    pub fn with_permissions(self, permissions: RoaringBitmap) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Adds the given permission to the account.
    pub fn grant_permission<P: Into<u32>>(&mut self, permission: P) {
        self.permissions.insert(permission.into());
    }

    /// Removes the given permission from the account.
    pub fn revoke_permission<P: Into<u32>>(&mut self, permission: P) {
        self.permissions.remove(permission.into());
    }
}

#[cfg(feature = "storage-seaorm")]
impl<R, G> TryFrom<crate::infrastructure::storage::sea_orm::models::account::Model>
    for Account<R, G>
where
    R: AccessHierarchy + Eq + std::fmt::Display + Clone,
    Vec<R>: CommaSeparatedValue,
    G: Eq + Clone,
    Vec<G>: CommaSeparatedValue,
{
    type Error = String;

    fn try_from(
        value: crate::infrastructure::storage::sea_orm::models::account::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self::new_with_account_id(
            &value.account_id,
            &value.user_id,
            &Vec::<R>::from_csv(&value.roles)?,
            &Vec::<G>::from_csv(&value.groups)?,
        ))
    }
}
