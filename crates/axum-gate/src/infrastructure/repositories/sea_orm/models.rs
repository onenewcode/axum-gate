//! SeaORM persistence models for accounts and credentials.
//!
//! These modules define the database entities used internally by `SeaOrmRepository`.
//! Most users of the library interact only with the repository traits. Import these
//! models if you need to perform custom migrations, schema generation, or direct
//! queries outside the provided repository abstraction.
//!
//! Submodules exposed:
//! * `account`
//! * `credentials`

pub mod account;
pub mod credentials;
pub mod permission_mapping;
