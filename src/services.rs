//! Different services available within `axum-gate`.
use crate::Error;
use crate::credentials::{Credentials, HashedCredentials};
use crate::passport::Passport;
use serde::{Serialize, de::DeserializeOwned};

/// Methods for encoding and decoding payload.
pub trait CodecService
where
    Self: Clone,
    Self::Payload: Serialize + DeserializeOwned,
{
    /// The payload that can be encoded.
    type Payload;

    /// Encodes the given payload.
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>, Error>;
    /// Decodoes the given payload.
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload, Error>;
}

/// Responsible for verification of a secret belonging to an identifier.
///
/// Implementing this service enables the application to verify the secret without
/// the necessity to store the secret in memory. For example if you are using a database, you can
/// directly execute the validation in a query that means the correct secret is not transferred
/// over the wire.
///
/// # Why not integrated into [CredentialsStorageService]?
///
/// See documentation of [CredentialsStorageService].
pub trait CredentialsVerifierService {
    /// Returns `true` if the given secret matches the one in your secret storage.
    fn verify_credentials<Id, Secret, Hasher>(
        &self,
        credentials: &Credentials<Id, Secret>,
        hasher: Hasher,
    ) -> impl Future<Output = Result<bool, Error>>
    where
        Hasher: SecretsHashingService,
        Id: std::hash::Hash + Eq,
        Secret: std::hash::Hash + Eq;
}

/// Responsible for the storage of credentials.
///
/// Intentionally does not have a method to retrieve the credentials as they
/// should only be used for authentication.
///
/// # Why is there no verification or method to retrieve the credentials?
///
/// Verification of the credentials has been outsourced to [CredentialsVerifierService] in order to
/// separate their concerns. A verification service does not necessarily require the
/// functionality of storing/updating/removing them.
pub trait CredentialsStorageService {
    /// Stores the credentials. Returns `true` on success, `false` if the [Credentials::id]
    /// already exists.
    fn store_credentials(
        &self,
        credentials: HashedCredentials,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Updates the credentials.
    fn update_credentials(
        &self,
        credentials: HashedCredentials,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Removed the credentials. Returns `true` on success, `false` if the [Credentials::id]
    /// does NOT exists.
    fn remove_credentials(
        &self,
        credentials: HashedCredentials,
    ) -> impl Future<Output = Result<bool, Error>>;
}

/// Responsible for hashing a plain value secret.
pub trait SecretsHashingService {
    /// Hashes the given plain value.
    fn hash_secret(&self, plain_value: &[u8]) -> Result<Vec<u8>, Error>;
    /// Compares the plain text to the hashed value, returns `true` if equal.
    fn verify_secret(&self, plain_value: &[u8], hashed_value: &[u8]) -> Result<bool, Error>;
}

/// A passport storage service contains a collection of passports that are
/// known to your application.
///
/// This is explicitly separated from the authentication mechanism used in [CredentialsVerifierService] to enable [Passport] sharing over the wire without
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
