//! Credentials definitions used for API, or storage.
use crate::Error;
use crate::{hashing::Argon2Hasher, services::SecretsHashingService};
use serde::{Deserialize, Serialize};

/// Defines credentials for a simple login based on an `id` and a `secret`.
///
/// This is mostly used for API communication. For storage in a database, see [HashedCredentials].
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
}

impl<Id> Credentials<Id, Vec<u8>> {
    /// Creates credentials using the given hasher.
    pub fn new_with_hasher<Hasher>(id: Id, secret: &[u8], hasher: &Hasher) -> Result<Self, Error>
    where
        Id: Into<Vec<u8>>,
        Hasher: SecretsHashingService,
    {
        let secret = hasher.hash_secret(secret)?;
        Ok(Self { id, secret })
    }
}
