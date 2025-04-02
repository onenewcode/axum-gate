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

/// Defines credentials for a simple login based on an `id` and a `secret`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashedCredentials {
    /// The identification of the user, eg. a username.
    pub id: Vec<u8>,
    /// The secret of the user, eg. a password.
    pub secret: Vec<u8>,
}

impl HashedCredentials {
    /// Creates hashed credentials using [Argon2Hasher].
    pub fn new_argon2<Id, Secret>(id: &Id, secret: &Secret) -> Result<Self, Error>
    where
        Id: Into<Vec<u8>> + Clone,
        Secret: Into<Vec<u8>> + Clone,
    {
        let hasher = Argon2Hasher::default();
        let id: Id = (*id).clone();
        let id = hasher.hash_secret(&id.into())?;
        let secret: Secret = (*secret).clone();
        let secret = hasher.hash_secret(&secret.into())?;
        Ok(Self { id, secret })
    }

    /// Creates hashed credentials using the given hasher.
    pub fn new_with_hasher<Id, Secret, Hasher>(
        id: Id,
        secret: Secret,
        hasher: &Hasher,
    ) -> Result<Self, Error>
    where
        Id: Into<Vec<u8>>,
        Secret: Into<Vec<u8>>,
        Hasher: SecretsHashingService,
    {
        let id = hasher.hash_secret(&id.into())?;
        let secret = hasher.hash_secret(&secret.into())?;
        Ok(Self { id, secret })
    }
}
