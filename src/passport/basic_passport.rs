//! Passports are the identification card for a user. Traditionally known as `Account`.
use super::Passport;
use crate::roles::BasicRole;
use crate::{BasicGroup, Error};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A passport contains basic information about a user.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BasicPassport<Id> {
    /// The unique id of the passport. For example username, email or some string of your choice.
    pub id: Id,
    /// A list of scopes that the user can access.
    pub groups: HashSet<BasicGroup>,
    /// Type of this passport.
    pub roles: HashSet<BasicRole>,
    /// Wether the passport is disabled.
    pub disabled: bool,
    /// Whether the used email for this passport has been verified.
    pub email_verified: bool,
    /// Determines when this passport expires.
    pub expires_at: DateTime<Utc>,
}

impl<Id> BasicPassport<Id>
where
    Id: ToOwned<Owned = Id>,
{
    /// Creates a new passport with [BasicPassport::disabled] and [BasicPassport::email_verified] set to `false`. The [expires_at](BasicPassport::expires_at) is set to 104 weeks.
    pub fn new(id: &Id, groups: &[&str], roles: &[BasicRole]) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_owned(),
            groups: HashSet::from_iter(groups.into_iter().map(|i| BasicGroup::new(i))),
            roles: HashSet::from_iter(roles.into_iter().map(|i| i.to_owned())),
            disabled: false,
            email_verified: false, // always require user to confirm it
            expires_at: chrono::Utc::now()
                + TimeDelta::try_weeks(104).ok_or(Error::Passport(format!(
                    "Internal server error. Could not create TimeDelta with \
                     two years."
                )))?,
        })
    }
}

impl<Id> Passport for BasicPassport<Id>
where
    Id: std::fmt::Display,
{
    type Id = Id;
    type Group = BasicGroup;
    type Role = BasicRole;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn roles(&self) -> &HashSet<BasicRole> {
        &self.roles
    }

    fn groups(&self) -> &HashSet<BasicGroup> {
        &self.groups
    }
}
