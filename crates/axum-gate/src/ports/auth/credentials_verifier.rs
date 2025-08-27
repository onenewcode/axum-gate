use crate::domain::entities::Credentials;
use crate::domain::values::VerificationResult;
use crate::errors::Result;

use std::future::Future;

/// Checks whether the given [Credentials] match to the one that is stored.
pub trait CredentialsVerifier<Id> {
    /// Verifies the given credentials.
    fn verify_credentials(
        &self,
        credentials: Credentials<Id>,
    ) -> impl Future<Output = Result<VerificationResult>>;
}
