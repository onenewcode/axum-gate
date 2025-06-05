//! Secrets hashing, verification models.
use crate::{
    Error,
    hashing::{HashedValue, VerificationResult},
    services::HashingService,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a secret that is bound to an [Account](crate::Account).
///
/// The `account_id` needs to be queried from an [AccountStorage](crate::services::AccountStorageService) to be able to create a correct secret.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secret {
    /// The [account id](crate::Account::account_id) that this secret belongs to.
    pub account_id: Uuid,
    /// The actual secret.
    pub secret: HashedValue,
}

impl Secret {
    /// Creates a new instance with the given id and secret.
    pub fn new<Hasher: HashingService>(
        account_id: &Uuid,
        plain_secret: &str,
        hasher: Hasher,
    ) -> Result<Self> {
        let secret = hasher
            .hash_value(plain_secret)
            .map_err(|e| Error::Hashing(e.to_string()))?;
        Ok(Self {
            account_id: account_id.clone(),
            secret,
        })
    }

    /// Verifies the given plain value to the stored one.
    pub fn verify<Hasher: HashingService>(
        &self,
        plain_secret: &str,
        hasher: Hasher,
    ) -> Result<VerificationResult> {
        hasher.verify_value(plain_secret, &self.secret)
    }
}
