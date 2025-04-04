//! Fully customizable role based JWT auth for axum.
//!
//! # Examples
//! - A pre-defined implementation of [SecretsHashingService](crate::secrets::SecretsHashingService)
//! can be found at [Argon2Hasher](crate::secrets::Argon2Hasher) that is used to hash credentials
//! before persisting it using [CredentialsStorageService](crate::storage::CredentialsStorageService)
//! - An example for a [CredentialsStorageService](crate::storage::CredentialsStorageService) /
//! [CredentialsVerifierService](crate::credentials::CredentialsVerifierService) used for
//! authentication can be found at [CredentialsMemoryStorage](crate::storage::CredentialsMemoryStorage)
#![deny(missing_docs)]

pub mod codecs;
pub mod credentials;
mod errors;
pub mod gate;
pub mod jwt;
pub mod passport;
pub mod roles;
pub mod route_handlers;
pub mod secrets;
pub mod storage;

pub use errors::Error;
pub use jsonwebtoken;
