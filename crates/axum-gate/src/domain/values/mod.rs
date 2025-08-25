//! Domain values module.
//!
//! Contains value objects and domain-specific types that represent
//! important concepts in the authentication and authorization domain.

mod secrets;
mod verification;

pub use secrets::Secret;
pub use verification::VerificationResult;
