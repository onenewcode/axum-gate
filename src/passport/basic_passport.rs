//! Passports are the identification card for a user. Traditionally known as `Account`.
use super::Passport;
use crate::Error;
use crate::roles::BasicRole;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A passport contains basic information about a user.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BasicPassport {
    /// The unique id of the passport. For example username, email or some string of your choice.
    pub id: String,
    /// A list of scopes that the user can access.
    pub groups: HashSet<String>,
    /// Type of this passport.
    pub roles: HashSet<BasicRole>,
    /// Wether the passport is disabled.
    pub disabled: bool,
    /// Whether the used email for this passport has been verified.
    pub email_verified: bool,
    /// Determines when this passport expires.
    pub expires_at: DateTime<Utc>,
}

impl BasicPassport {
    /// Creates a new passport with [BasicPassport::disabled] and [BasicPassport::confirmed] set to `false`.
    pub fn new(id: &str, groups: &[&str], roles: &[BasicRole]) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_string(),
            groups: HashSet::from_iter(groups.into_iter().map(|i| i.to_string())),
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

impl Passport for BasicPassport {
    type Id = String;
    type Group = String;
    type Role = BasicRole;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn roles(&self) -> &HashSet<BasicRole> {
        &self.roles
    }

    fn groups(&self) -> &HashSet<String> {
        &self.groups
    }
}
