/// Errors that can occur within the use of `axum-gate`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// This error occurs in combination with a [Passport](crate::passport::Passport) operation.
    #[error("Passport error: {0}")]
    Passport(String),
    /// This error occurs in combination with a
    /// [PassportStorageService](crate::storage::PassportStorageService) operation.
    #[error("PassportStorage error: {0}")]
    PassportStorage(String),
    /// This error occurs in combination with a
    /// [CodecService](crate::codecs::CodecService) operation.
    #[error("CodecService error: {0}")]
    Codec(String),
    /// This error occurs in combination with a
    /// [secrets](crate::secrets) operation.
    #[error("Hashing error: {0}")]
    Hashing(String),
    /// This error occurs in combination with authentication.
    #[error("Authentication error: {0}")]
    Authentication(String),
    /// This error occurs in combination with the credentials storage.
    #[error("Credentials storage error: {0}")]
    CredentialsStorage(String),
    /// This error occurs during a generic storage operation.
    #[error("Storage error: {0}")]
    Storage(String),
}
