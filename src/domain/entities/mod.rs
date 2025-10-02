//! Domain entities module.
//!
//! Contains the core business entities that represent the fundamental
//! concepts in the authentication and authorization domain.

/// Core account entity containing user authorization information.
pub mod account;
/// Credentials entity for authentication.
pub mod credentials;
/// Group entity representing user groups.
pub mod group;
/// Role entity for role-based access control.
pub mod role;

pub use account::Account;
pub use credentials::Credentials;
pub use group::Group;
pub use role::Role;
