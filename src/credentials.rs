//! Credentials definitions used for API, or storage.
use serde::{Deserialize, Serialize};

/// Defines credentials for a simple login based on a `user_id` and a `secret`.
///
/// This struct is also used to store the secret in a storage. For this, the `Id` is set
/// to the [Account::account_id](crate::Account::account_id). This enables the possibility to
/// separate secret storage from the account data. This enhances security if the secret storage is
/// not equal to the account storage as the `id` is only a reference. The secret cannot directly
/// combined with an account without compromising the account storage as well.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub user_id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates a new instance with the given id and secret.
    pub fn new(user_id: &Id, secret: &str) -> Self
    where
        Id: ToOwned<Owned = Id>,
    {
        Self {
            user_id: user_id.to_owned(),
            secret: secret.to_string(),
        }
    }
}
