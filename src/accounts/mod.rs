use crate::utils::AccessHierarchy;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An account contains authorization information about a user.
#[derive(Serialize, Deserialize)]
pub struct Account<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// The unique identifier of the account which has been generated on registration.
    ///
    /// This identifier is the loosely connection to the [Credentials](crate::Credentials) in
    /// a [SecretStorageService](crate::services::SecretStorageService).
    pub account_id: Uuid,
    /// The user id for this account. This should be unique within your application.
    pub user_id: String,
    /// Roles of this account.
    pub roles: Vec<R>,
    /// Groups the account belongs to.
    pub groups: Vec<G>,
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
        }
    }
}
