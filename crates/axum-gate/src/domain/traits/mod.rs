//! Domain traits module.
//!
//! Contains interfaces and contracts that define the behavior
//! expected from domain services and external dependencies.

mod access_hierarchy;
mod comma_separated_value;

pub use access_hierarchy::AccessHierarchy;
pub use comma_separated_value::CommaSeparatedValue;
