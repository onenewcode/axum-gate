use crate::secrets::Secret;

use anyhow::Result;
use uuid::Uuid;

/// Responsible for the storage of secrets.
///
/// Intentionally does not have a method to retrieve the credentials as they
/// should only be used for authentication.
pub trait SecretStorageService {
    /// Stores the secret. Returns `true` on success, `false` if the [Secret::account_id]
    /// already exists.
    fn store_secret(&self, secret: Secret) -> impl Future<Output = Result<bool>>;

    /// Updates the credentials. The `secret` should be plain text, hashing is done by the
    /// storage implementation.
    fn update_secret(&self, secret: Secret) -> impl Future<Output = Result<()>>;

    /// Removes the credentials with the given id. Returns `true` on success, `false` if the
    /// [Secret::account_id] does NOT exists.
    fn delete_secret(&self, id: &Uuid) -> impl Future<Output = Result<bool>>;
}
