/// Errors that can occur within the use of `axum-gate`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// This error occurs in combination with a [Passport](crate::passport::Passport) operation.
    #[error("Passport error: {0}")]
    Passport(String),
    /// This error occurs in combination with a
    /// [PassportRegister](crate::passport_register::PassportRegister) operation.
    #[error("PassportRegister error: {0}")]
    PassportRegister(String),
    /// This error occurs in combination with a
    /// [CodecService](crate::services::CodecService) operation.
    #[error("CodecService error: {0}")]
    Codec(String),
    /// This error occurs in combination with a
    /// [hashing](crate::hashing) operation.
    #[error("Hashing error: {0}")]
    Hashing(String),
}
