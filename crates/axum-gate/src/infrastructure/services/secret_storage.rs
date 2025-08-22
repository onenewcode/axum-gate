use crate::domain::values::secrets::Secret;

use anyhow::Result;
use uuid::Uuid;

/// Responsible for the storage of secrets.
pub trait SecretStorageService {
    /// Stores the secret.
    ///
    /// Returns `true` on success, `false` if the [Secret::account_id]
    /// already exists. The secret will not be updated in this case.
    fn store_secret(&self, secret: Secret) -> impl Future<Output = Result<bool>>;

    /// Updates the given [Secret].
    fn update_secret(&self, secret: Secret) -> impl Future<Output = Result<()>>;

    /// Removes the [Secret] belonging to the given id. Returns `true` on success, `false` if the
    /// [Secret::account_id] does NOT exists.
    fn delete_secret(&self, id: &Uuid) -> impl Future<Output = Result<bool>>;
}
