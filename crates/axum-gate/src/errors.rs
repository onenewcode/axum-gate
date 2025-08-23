/// Errors that can occur within the use of `axum-gate`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// This error occurs in combination with a
    /// [CodecService](crate::services::CodecService) operation.
    #[error("CodecService error: {0}")]
    Codec(String),
    /// This error occurs in combination with a
    /// [hashing](crate::hashing) operation.
    #[error("Hashing error: {0}")]
    Hashing(String),
    /// This error occurs in combination with a
    /// [SecretRepository](crate::services::SecretRepositoryService) operation.
    #[error("SecretRepositoryService error: {0}")]
    SecretRepository(String),
    /// This error occurs in combination with a
    /// [AccountRepositoryService](crate::services::AccountRepositoryService) operation.
    #[error("AccountRepositoryService error: {0}")]
    AccountRepository(String),
    /// This error occurs in combination with a generic Repository operation.
    #[error("Repository error: {0}")]
    Repository(String),
}
