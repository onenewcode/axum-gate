//! A [Passport] identifies a user.

mod basic_passport;

pub use self::basic_passport::BasicPassport;
use crate::Error;
use crate::roles::RoleHierarchy;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashSet;
use std::fmt::{Debug, Display};

/// A passport contains basic information about a user that can be used for authorization.
pub trait Passport {
    /// The unique identifier type of the passport.
    type Id: Display;
    /// Roles that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Role: Debug + Default + Eq + RoleHierarchy + Serialize + DeserializeOwned;
    /// The groups that this passport belongs to. Serde is required to store them
    /// in JWT.
    type Group: Eq + Serialize + DeserializeOwned;

    /// Returns the unique identifier of the passport.
    fn id(&self) -> &Self::Id;

    /// Returns the roles this passport belongs to.
    fn roles(&self) -> &HashSet<Self::Role>;

    /// Returns the groups this passport belongs to.
    fn groups(&self) -> &HashSet<Self::Group>;
}

/// A passport storage service contains a collection of passports that are
/// known to your application.
///
/// This is explicitly separated from the authentication mechanism used in [CredentialsVerifierService] to enable [Passport] sharing over the wire without
/// transferring the secret that authenticates the user.
///
/// `ID` is the unique identifier type for a [Passport].
pub trait PassportStorageService<P>
where
    P: Passport + Clone,
{
    /// Returns the passport for the given `passport_id`.
    fn passport(&self, passport_id: &P::Id) -> impl Future<Output = Result<Option<P>, Error>>;
    /// Stores the given passport in the register returning its ID for further usage.
    fn store_passport(&mut self, passport: P) -> impl Future<Output = Result<P::Id, Error>>;
    /// Removes the passport with the given `passport_id`.
    fn remove_passport(&self, passport_id: &P::Id) -> impl Future<Output = Result<bool, Error>>;
}
