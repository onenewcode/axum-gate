//! Credentials definitions used for API, or storage.
use crate::Error;
use crate::secrets::SecretsHashingService;
use serde::{Deserialize, Serialize};

/// Responsible for verification of a secret belonging to an identifier.
///
/// Implementing this service enables the application to verify the secret without
/// the necessity to store the secret in memory. For example if you are using a database, you can
/// directly execute the validation in a query that means the correct secret is not transferred
/// over the wire.
///
/// # Why not integrated into CredentialsStorageService?
///
/// See documentation of [CredentialsStorageService](crate::storage::CredentialsStorageService).
pub trait CredentialsVerifierService<Id, Secret> {
    /// Returns `true` if the given secret matches the one in your secret storage.
    fn verify_credentials<Hasher>(
        &self,
        credentials: &Credentials<Id, Secret>,
        hasher: &Hasher,
    ) -> impl Future<Output = Result<bool, Error>>
    where
        Hasher: SecretsHashingService;
}

/// Defines credentials for a simple login based on an `id` and a `secret`.
///
/// It can be used for API communication, or in a persisting storage like a database using a
/// hasher, see [Credentials::hash_secret].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id, Secret> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: Secret,
}

impl<Id, Secret> Credentials<Id, Secret> {
    /// Creates a new ticket with the given id and secret.
    pub fn new(id: Id, secret: Secret) -> Self {
        Self { id, secret }
    }

    /// Hashes the secret with the given [SecretsHashingService].
    pub fn hash_secret<Hasher>(self, hasher: &Hasher) -> Result<Credentials<Id, Vec<u8>>, Error>
    where
        Secret: Into<Vec<u8>>,
        Hasher: SecretsHashingService,
    {
        let secret = hasher.hash_secret(&self.secret.into())?;
        Ok(Credentials {
            id: self.id,
            secret,
        })
    }
}
