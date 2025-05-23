#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod access_hierarchy;
mod account;
pub mod codecs;
pub mod credentials;
mod errors;
mod gate;
mod groups;
pub mod jwt;
pub mod passport;
pub mod roles;
pub mod route_handlers;
pub mod secrets;
pub mod storage;

pub use access_hierarchy::AccessHierarchy;
pub use account::Account;
pub use cookie;
pub use errors::Error;
pub use gate::Gate;
pub use groups::BasicGroup;
pub use jsonwebtoken;

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
