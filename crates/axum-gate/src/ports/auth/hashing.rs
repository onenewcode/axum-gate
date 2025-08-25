use crate::domain::values::VerificationResult;
use crate::infrastructure::hashing::HashedValue;

use anyhow::Result;

/// Responsible for hashing a plain value.
pub trait HashingService {
    /// Hashes the given plain value.
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue>;
    /// Verifies that `plain_value` matches the `hashed_value` by using the implementors hashing,
    /// function.
    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult>;
}
