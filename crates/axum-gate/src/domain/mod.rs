//! Domain layer containing the core business logic and entities.
//!
//! This layer is the heart of the hexagonal architecture and contains:
//! - Entities: Core business objects
//! - Services: Domain business logic
//! - Traits: Domain interfaces and contracts
//! - Values: Value objects and domain-specific types

pub mod entities;
pub mod errors;
pub mod services;
pub mod traits;
pub mod values;
