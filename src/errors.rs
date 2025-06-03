/// Errors that can occur within the use of `axum-gate`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// This error occurs in combination with a
    /// [CodecService](crate::codecs::CodecService) operation.
    #[error("CodecService error: {0}")]
    Codec(String),
    /// This error occurs in combination with a
    /// [secrets](crate::secrets) operation.
    #[error("Hashing error: {0}")]
    Hashing(String),
    /// This error occurs in combination with a
    /// [SecretStorage](crate::services::SecretStorageService) operation.
    #[error("SecretStorageService error: {0}")]
    SecretStorage(String),
    /// This error occurs in combination with a
    /// [AccountStorageService](crate::services::AccountStorageService) operation.
    #[error("AccountStorageService error: {0}")]
    AccountStorage(String),
}
