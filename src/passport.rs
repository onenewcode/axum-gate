//! A [Passport] identifies a user.

use crate::AccessHierarchy;
use std::collections::HashSet;

/// A passport contains basic information about a user that can be used for authorization.
pub trait Passport {
    /// The unique identifier type of the passport.
    type Id;
    /// Roles that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Role: AccessHierarchy + Eq;
    /// The groups that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Group: Eq;

    /// Returns the unique identifier of the passport.
    fn id(&self) -> &Self::Id;

    /// Returns the username of the owner of this passport. This is usually unique
    /// for your application.
    fn username(&self) -> &str;

    /// Returns the roles this passport belongs to.
    fn roles(&self) -> &HashSet<Self::Role>;

    /// Returns the groups this passport belongs to.
    fn groups(&self) -> &HashSet<Self::Group>;
}
