//! Repository implementations.

pub mod memory;
#[cfg(feature = "storage-seaorm")]
pub mod sea_orm;
#[cfg(feature = "storage-surrealdb")]
pub mod surrealdb;

#[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
pub use repository_additions::*;

#[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
mod repository_additions {
    /// Configurable table names used by the storage backends.
    ///
    /// Most users can rely on `TableNames::default()`. Override only if your existing
    /// database schema uses different table names.
    #[derive(Clone, Debug)]
    pub struct TableNames {
        /// Accounts table (stores user id, groups, roles).
        pub accounts: String,
        /// Credentials table (stores hashed secrets).
        pub credentials: String,
    }

    impl Default for TableNames {
        fn default() -> Self {
            Self {
                accounts: "axum-gate-accounts".to_string(),
                credentials: "axum-gate-credentials".to_string(),
            }
        }
    }
}
