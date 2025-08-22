//! Repository port definitions.
//!
//! This module contains trait definitions for repositories that abstract
//! data persistence operations. These traits define the contracts that
//! must be implemented by infrastructure layer adapters.

// TODO: Define repository traits
// - AccountRepository: For account persistence operations
// - CredentialsRepository: For credential storage and retrieval
// - RoleRepository: For role management
// - GroupRepository: For group management
// - SecretRepository: For secret storage operations

// Example repository trait structure:
// pub trait AccountRepository {
//     async fn save(&self, account: Account) -> Result<Account, Error>;
//     async fn find_by_id(&self, id: AccountId) -> Result<Option<Account>, Error>;
//     async fn delete(&self, id: AccountId) -> Result<(), Error>;
// }
