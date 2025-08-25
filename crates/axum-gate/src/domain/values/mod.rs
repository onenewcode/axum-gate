//! Domain values module.
//!
//! Contains value objects and domain-specific types that represent
//! important concepts in the authentication and authorization domain.

mod access_scope;
mod secrets;
mod verification;

pub use access_scope::AccessScope;
pub use secrets::Secret;
pub use verification::VerificationResult;
