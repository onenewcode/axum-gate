//! Passports are the identification card for a user. Traditionally known as `Account`.
use crate::AccessHierarchy;
#[cfg(feature = "storage-seaorm")]
use crate::CommaSeparatedValue;
use crate::Group;
use crate::passport::Passport;

use std::collections::HashSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A passport contains basic information about a user.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account<Id, R>
where
    R: std::hash::Hash + Eq,
{
    /// A unique identifier for the account. This is mainly used for working with a
    /// database.
    pub id: Id,
    /// The unique id of the account. For example username or email.
    pub username: String,
    /// A list of scopes that the user can access.
    pub groups: HashSet<Group>,
    /// Type of this passport.
    pub roles: HashSet<R>,
}

impl<Id, R> Account<Id, R>
where
    Id: ToOwned<Owned = Id>,
    R: std::hash::Hash + Eq + Clone,
{
    /// Creates a new passport with the given id, username, groups and roles.
    pub fn new(id: &Id, username: &str, groups: &[&str], roles: &[R]) -> Self
    where
        Id: ToOwned<Owned = Id>,
    {
        let roles = roles.to_vec();
        Self {
            id: id.to_owned(),
            username: username.to_owned(),
            groups: HashSet::from_iter(groups.into_iter().map(|i| Group::new(i))),
            roles: HashSet::from_iter(roles.into_iter()),
        }
    }
}

impl<Id, R> Passport for Account<Id, R>
where
    Id: std::fmt::Display,
    R: AccessHierarchy + std::hash::Hash + Eq + Serialize + DeserializeOwned,
{
    type Id = Id;
    type Group = Group;
    type Role = R;

    fn id(&self) -> &Id {
        &self.id
    }

    fn username(&self) -> &str {
        self.username.as_str()
    }

    fn roles(&self) -> &HashSet<R> {
        &self.roles
    }

    fn groups(&self) -> &HashSet<Group> {
        &self.groups
    }
}

/*
#[cfg(feature = "storage-seaorm")]
impl<R> TryFrom<crate::storage::sea_orm::models::account::Model> for Account<i32, R>
where
    R: Eq + std::hash::Hash + std::fmt::Display + Clone,
    HashSet<R>: CommaSeparatedValue,
{
    type Error = String;

    fn try_from(
        value: crate::storage::sea_orm::models::account::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            username: value.username,
            groups: HashSet::<Group>::from_csv(&value.groups)?,
            roles: HashSet::<R>::from_csv(&value.roles)?,
        })
    }
}
 */
