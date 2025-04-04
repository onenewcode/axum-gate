//! Storage implementations.

mod credentials_memory_storage;
mod passport_storage;

use crate::Error;
use crate::credentials::Credentials;
use crate::passport::Passport;
pub use credentials_memory_storage::CredentialsMemoryStorage;
pub use passport_storage::PassportMemoryStorage;

/// A passport storage service contains a collection of passports that are
/// known to your application.
///
/// This is explicitly separated from the authentication mechanism used in [CredentialsVerifierService](crate::credentials::CredentialsVerifierService) to enable [Passport] sharing over the wire without
/// transferring the secret that authenticates the user.
///
/// `ID` is the unique identifier type for a [Passport].
pub trait PassportStorageService<P>
where
    P: Passport + Clone,
{
    /// Returns the passport for the given `passport_id`.
    fn passport(&self, passport_id: &P::Id) -> impl Future<Output = Result<Option<P>, Error>>;
    /// Stores the given passport in the register returning its ID for further usage.
    fn store_passport(&mut self, passport: P) -> impl Future<Output = Result<P::Id, Error>>;
    /// Removes the passport with the given `passport_id`.
    fn remove_passport(&self, passport_id: &P::Id) -> impl Future<Output = Result<bool, Error>>;
}

/// Responsible for the storage of credentials.
///
/// Intentionally does not have a method to retrieve the credentials as they
/// should only be used for authentication.
///
/// # Why is there no verification or method to retrieve the credentials?
///
/// Verification of the credentials has been outsourced to [CredentialsVerifierService](crate::credentials::CredentialsVerifierService) in order to
/// separate their concerns. A verification service does not necessarily require the
/// functionality of storing/updating/removing them.
pub trait CredentialsStorageService<Id, Secret> {
    /// Stores the credentials. Returns `true` on success, `false` if the [Credentials::id]
    /// already exists.
    fn store_credentials(
        &self,
        credentials: Credentials<Id, Secret>,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Updates the credentials.
    fn update_credentials(
        &self,
        credentials: Credentials<Id, Secret>,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Removed the credentials. Returns `true` on success, `false` if the [Credentials::id]
    /// does NOT exists.
    fn remove_credentials(
        &self,
        credentials: Credentials<Id, Secret>,
    ) -> impl Future<Output = Result<bool, Error>>;
}
