//! Storage implementations.

mod credentials_memory_storage;
mod passport_storage;

pub use credentials_memory_storage::CredentialsMemoryStorage;
pub use passport_storage::PassportMemoryStorage;
