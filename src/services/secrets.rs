use crate::secrets::{HashedSecret, VerificationResult};

use anyhow::Result;

/// Responsible for hashing a plain value secret.
pub trait SecretsHashingService {
    /// Hashes the given plain value.
    fn hash_secret(&self, plain_value: &str) -> Result<HashedSecret>;
    /// Verifies that `plain_value` matches the `hashed_value` by using the implementors hashing,
    /// function. Returns `true` if equal.
    fn verify_secret(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult>;
}
