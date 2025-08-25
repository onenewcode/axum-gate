//! Domain values module.
//!
//! Contains value objects and domain-specific types that represent
//! important concepts in the authentication and authorization domain.

pub mod secrets;
pub mod verification;

pub use secrets::*;
pub use verification::VerificationResult;
