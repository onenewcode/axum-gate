//! Domain values module.
//!
//! Contains value objects and domain-specific types that represent
//! important concepts in the authentication and authorization domain.

mod access_scope;
mod permission_id;
mod permission_mapping;
mod permissions;
mod secrets;
mod static_token_authorized;
mod verification;

pub use access_scope::AccessScope;
pub use permission_id::PermissionId;
pub use permission_mapping::{PermissionMapping, PermissionMappingError};
pub use permissions::Permissions;
pub use secrets::Secret;
pub use static_token_authorized::StaticTokenAuthorized;
pub use verification::VerificationResult;
