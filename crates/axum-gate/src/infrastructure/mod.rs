//! Infrastructure layer containing external dependencies and implementations.
//!
//! This layer contains adapters and implementations for external systems:
//! - Web: HTTP/Web framework integrations and handlers
//! - Storage: Database and persistence implementations
//! - JWT: JSON Web Token implementation details
//! - Hashing: Password hashing and cryptographic implementations
pub mod hashing;
pub mod jwt;
pub mod storage;
pub mod web;
