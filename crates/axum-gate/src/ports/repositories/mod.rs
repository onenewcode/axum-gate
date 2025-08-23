//! Repository port definitions.
//!
//! This module contains trait definitions for repositories that abstract
//! data persistence operations. These traits define the contracts that
//! must be implemented by infrastructure layer adapters.

mod account;
mod secret;

pub use account::AccountRepository;
pub use secret::SecretRepository;

// TODO: Define additional repository traits
// - CredentialsRepository: For credential storage and retrieval
// - RoleRepository: For role management
// - GroupRepository: For group management
// - SecretRepository: For secret storage operations
