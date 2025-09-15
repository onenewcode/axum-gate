//! Ports module defining interfaces for external dependencies.
//!
//! This module contains the port interfaces that define contracts
//! between the application layer and external systems. These ports
//! are implemented by adapters in the infrastructure layer.

pub(crate) mod auth;
pub(crate) mod errors;
pub(crate) mod repositories;

mod codecs;

pub use codecs::Codec;
