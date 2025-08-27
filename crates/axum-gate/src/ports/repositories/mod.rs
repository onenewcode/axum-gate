//! Repository port definitions.
//!
//! This module contains trait definitions for repositories that abstract
//! data persistence operations. These traits define the contracts that
//! must be implemented by infrastructure layer adapters.

mod account;
mod secret;

pub use account::AccountRepository;
pub use secret::SecretRepository;
