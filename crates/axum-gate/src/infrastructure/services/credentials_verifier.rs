use crate::Credentials;
use crate::infrastructure::hashing::VerificationResult;

use anyhow::Result;

/// Checks whether the given [Credentials] match to the one that is stored.
pub trait CredentialsVerifierService<Id> {
    /// Verifies the given credentials.
    fn verify_credentials(
        &self,
        credentials: Credentials<Id>,
    ) -> impl Future<Output = Result<VerificationResult>>;
}
