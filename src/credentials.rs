//! Credentials definitions used for API, or storage.
use crate::Error;
use serde::{Deserialize, Serialize};

/// Responsible for verification of a secret belonging to an identifier.
///
/// Implementing this service enables the application to reduce the amount of times a correct secret
/// is transferred. For example instead of querying the credentials and verify it on the client, it
/// is recommended to send a query to the database and verify it on this
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
/// It can be used for API communication, or in a persisting storage like a database using a
/// hasher, see [Credentials::hash_secret].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates a new instance with the given id and secret.
    pub fn new(id: Id, secret: &str) -> Self {
        Self {
            id,
            secret: secret.to_string(),
        }
    }
}
