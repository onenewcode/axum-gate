use crate::hashing::{HashedValue, VerificationResult};

use anyhow::Result;

/// Responsible for hashing a plain value secret.
pub trait HashingService {
    /// Hashes the given plain value.
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue>;
    /// Verifies that `plain_value` matches the `hashed_value` by using the implementors hashing,
    /// function. Returns `true` if equal.
    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult>;
}
