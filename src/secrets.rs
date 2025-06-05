//! Secrets hashing, verification models.
use crate::hashing::HashedValue;

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
    pub fn new(account_id: &Uuid, secret: &HashedValue) -> Self {
        Self {
            account_id: account_id.clone(),
            secret: secret.clone(),
        }
    }
}
