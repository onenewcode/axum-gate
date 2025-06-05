use crate::hashing::VerificationResult;
use crate::secrets::Secret;

use anyhow::Result;

/// Verifies the given [Secret].
pub trait SecretVerifierService {
    /// Verifies the given [Secret].
    fn verify_secret(&self, secret: Secret) -> impl Future<Output = Result<VerificationResult>>;
}
