//! Comma-separated value conversion trait for SeaORM storage.
//!
//! This module provides the [`CommaSeparatedValue`] trait for converting between
//! complex types and their comma-separated string representations. This is primarily
//! used by the SeaORM storage backend to serialize/deserialize collections like
//! roles and groups into database-friendly formats.
//!
//! # Usage
//!
//! The trait is typically implemented for collections that need to be stored
//! as comma-separated strings in SQL databases:
//!
//! ```rust
//! use axum_gate::comma_separated_value::CommaSeparatedValue;
//!
//! impl CommaSeparatedValue for Vec<String> {
//!     fn into_csv(self) -> String {
//!         self.join(",")
//!     }
//!
//!     fn from_csv(value: &str) -> Result<Self, String> {
//!         if value.is_empty() {
//!             Ok(Vec::new())
//!         } else {
//!             Ok(value.split(',').map(|s| s.to_string()).collect())
//!         }
//!     }
//! }
//! ```
//!
//! # Note
//!
//! This module is only available when the `storage-seaorm` feature is enabled,
//! as it's specifically designed for SeaORM database storage requirements.

/// Conversion between a model and its CSV representation.
pub trait CommaSeparatedValue
where
    Self: Sized,
{
    /// Converts `self` into a comma separated value.
    fn into_csv(self) -> String;
    /// Converts the given slice into the model.
    fn from_csv(value: &str) -> Result<Self, String>;
}
