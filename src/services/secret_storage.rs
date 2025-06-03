use crate::{Credentials, secrets::VerificationResult};

use anyhow::Result;
use uuid::Uuid;

/// Responsible for the storage of secrets.
///
/// Intentionally does not have a method to retrieve the credentials as they
/// should only be used for authentication.
pub trait SecretStorageService {
    /// Stores the secret. Returns `true` on success, `false` if the [Credentials::id]
    /// already exists. The `secret` needs to be in plain text as hashing takes place in the
    /// storage implementation.
    fn store(&self, credentials: Credentials<Uuid>) -> impl Future<Output = Result<bool>>;

    /// Updates the credentials. The `secret` should be plain text, hashing is done by the
    /// storage implementation.
    fn update(&self, credentials: Credentials<Uuid>) -> impl Future<Output = Result<()>>;

    /// Removes the credentials with the given id. Returns `true` on success, `false` if the
    /// [Credentials::id] does NOT exists.
    fn delete(&self, id: &Uuid) -> impl Future<Output = Result<bool>>;

    /// Verifies the given plain value to the hashed one in the storage.
    fn verify(
        &self,
        credentials: Credentials<Uuid>,
    ) -> impl Future<Output = Result<VerificationResult>>;
}
