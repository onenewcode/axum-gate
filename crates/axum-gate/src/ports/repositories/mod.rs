//! Repository port definitions.
//!
//! This module contains trait definitions for repositories that abstract
//! data persistence operations. These traits define the contracts that
//! must be implemented by infrastructure layer adapters.

mod account;

pub use account::AccountRepository;

// TODO: Define additional repository traits
// - CredentialsRepository: For credential storage and retrieval
// - RoleRepository: For role management
// - GroupRepository: For group management
// - SecretRepository: For secret storage operations
