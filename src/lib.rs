//! Role based JWT auth for axum.
#![deny(missing_docs)]

pub mod codecs;
mod credentials;
mod errors;
pub mod passport;
pub mod passport_register;
mod role;
mod role_hierarchy;
pub mod services;

pub use credentials::Credentials;
pub use errors::Error;
pub use jsonwebtoken;
pub use role::Role;
pub use role_hierarchy::RoleHierarchy;
