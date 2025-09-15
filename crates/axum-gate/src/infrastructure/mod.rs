//! Infrastructure layer containing external dependencies and implementations.
//!
//! This layer contains adapters and implementations for external systems:
//! - Web: HTTP/Web framework integrations and handlers
//! - Repositories: Database and persistence implementations
//! - JWT: JSON Web Token implementation details
//! - Hashing: Password hashing and cryptographic implementations
pub(crate) mod errors;
pub(crate) mod hashing;
pub(crate) mod jwt;
pub(crate) mod repositories;
pub(crate) mod web;
