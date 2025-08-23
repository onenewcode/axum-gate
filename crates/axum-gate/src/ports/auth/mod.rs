//! Authentication port definitions.
//!
//! This module defines the port interfaces for authentication-related
//! external dependencies. These ports are implemented by adapters in
//! the infrastructure layer.

mod credentials_verifier;
mod hashing;

pub use credentials_verifier::CredentialsVerifier;
pub use hashing::HashingService;

// TODO: Define additional authentication ports such as:
// - AuthenticationPort: For external authentication providers
// - TokenValidationPort: For token validation services
// - CredentialStoragePort: For credential storage systems
// - SessionManagementPort: For session management systems
