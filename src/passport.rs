//! A [Passport] identifies a user.

mod basic_passport;

pub use self::basic_passport::BasicPassport;
use crate::roles::AccessHierarchy;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashSet;
use std::fmt::{Debug, Display};

/// A passport contains basic information about a user that can be used for authorization.
pub trait Passport {
    /// The unique identifier type of the passport.
    type Id: Display;
    /// Roles that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Role: Debug + Eq + AccessHierarchy + Serialize + DeserializeOwned;
    /// The groups that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Group: Debug + Eq + Serialize + DeserializeOwned;

    /// Returns the unique identifier of the passport.
    fn id(&self) -> &Self::Id;

    /// Returns the roles this passport belongs to.
    fn roles(&self) -> &HashSet<Self::Role>;

    /// Returns the groups this passport belongs to.
    fn groups(&self) -> &HashSet<Self::Group>;
}
