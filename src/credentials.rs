//! Credentials definitions used for API, or storage.
use crate::Error;

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Responsible for verification of a secret belonging to an identifier.
///
/// Implementing this service enables the application to reduce the amount of times a correct secret
/// is transferred. For example instead of querying the credentials and verify it on the client, it
/// is recommended to send a query to the database and verify it on the server. See
/// [SurrealDbStorage](crate::storage::surrealdb::SurrealDbStorage) implementation for reference.
///
/// # Why not integrated into CredentialsStorageService?
///
/// See documentation of [CredentialsStorageService](crate::storage::CredentialsStorageService).
pub trait CredentialsVerifierService<Id> {
    /// Returns `true` if the given secret matches the one in your secret storage.
    fn verify_credentials(
        &self,
        credentials: &Credentials<Id>,
    ) -> impl Future<Output = Result<bool, Error>>;
}

/// Defines credentials for a simple login based on an `id` and a `secret`.
///
/// This struct is also used to store the secret in a storage. For this, the `Id` is set
/// to the [Account::id](crate::Account::id). This enables the possibility to separate secret
/// storage from the account data. This enhances security if the secret storage is not equal to the
/// account storage as the `id` is only a reference. The secret cannot directly combined with an
/// account without compromising the account storage as well.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates a new instance with the given id and secret.
    pub fn new(id: &Id, secret: &str) -> Self
    where
        Id: ToOwned<Owned = Id>,
    {
        Self {
            id: id.to_owned(),
            secret: secret.to_string(),
        }
    }
}

/*
#[cfg(feature = "storage-seaorm")]
impl<Id> TryFrom<crate::storage::sea_orm::models::credentials::Model> for Credentials<Id>
where
    Id: From<i32>,
{
    type Error = String;

    fn try_from(
        value: crate::storage::sea_orm::models::credentials::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Some(Id::from(value.id)),
            username: value.username,
            secret: value.secret,
        })
    }
}
 */
