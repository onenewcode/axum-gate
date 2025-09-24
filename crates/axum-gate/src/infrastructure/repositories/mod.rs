//! Repository implementations.

pub mod memory;
#[cfg(feature = "storage-seaorm")]
pub mod sea_orm;
#[cfg(feature = "storage-surrealdb")]
pub mod surrealdb;

/// Table names used by the storage backends.
#[derive(strum::Display, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum TableName {
    /// Account storage table name.
    AxumGateAccounts,
    /// Credentials storage table name.
    AxumGateCredentials,
    /// Permission mappings storage table name.
    AxumGatePermissionMappings,
}
