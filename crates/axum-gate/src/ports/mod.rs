//! Ports module defining interfaces for external dependencies.
//!
//! This module contains the port interfaces that define contracts
//! between the application layer and external systems. These ports
//! are implemented by adapters in the infrastructure layer.

pub mod auth;
pub mod error;
pub mod repositories;

mod codecs;

pub use codecs::Codec;

// Re-exports will be added here when auth and repositories modules have content
// pub use auth::*;
// pub use repositories::*;
