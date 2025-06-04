//! Storage implementations.

pub mod memory;
/*
#[cfg(feature = "storage-seaorm")]
pub mod sea_orm;
*/
#[cfg(feature = "storage-surrealdb")]
pub mod surrealdb;

#[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
pub use storage_additions::*;

#[cfg(any(feature = "storage-surrealdb", feature = "storage-seaorm"))]
mod storage_additions {
    /// Table names that are used within the database.
    #[derive(Clone, Debug)]
    pub struct TableNames {
        /// Where accounts are being stored.
        pub accounts: String,
        /// Where credentials are stored.
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
