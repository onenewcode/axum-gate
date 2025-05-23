//! Passports are the identification card for a user. Traditionally known as `Account`.
use crate::CommaSeparatedValue;
use crate::passport::Passport;
use crate::roles::BasicRole;
use crate::{BasicGroup, Error};

use std::collections::HashSet;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

/// A passport contains basic information about a user.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account<Id, AccountId> {
    /// A customizable unique identifier for the account. This is mainly used for working with a
    /// database.
    pub id: Id,
    /// The unique id of the account. For example username, email or something of your choice.
    pub account_id: AccountId,
    /// A list of scopes that the user can access.
    pub groups: HashSet<BasicGroup>,
    /// Type of this passport.
    pub roles: HashSet<BasicRole>,
    /// Wether the passport is disabled.
    pub disabled: bool,
    /// Determines when this passport expires.
    pub expires_at: DateTime<Utc>,
}

impl<Id, AccountId> Account<Id, AccountId>
where
    Id: ToOwned<Owned = Id>,
    AccountId: ToOwned<Owned = AccountId>,
{
    /// Creates a new passport with [Account::disabled] and [Account::email_verified] set to `false`. The [expires_at](Account::expires_at) is set to 104 weeks.
    pub fn new(
        id: &Id,
        account_id: &AccountId,
        groups: &[&str],
        roles: &[BasicRole],
    ) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_owned(),
            account_id: account_id.to_owned(),
            groups: HashSet::from_iter(groups.into_iter().map(|i| BasicGroup::new(i))),
            roles: HashSet::from_iter(roles.into_iter().map(|i| i.to_owned())),
            disabled: false,
            expires_at: chrono::Utc::now()
                + TimeDelta::try_weeks(104).ok_or(Error::Passport(format!(
                    "Internal server error. Could not create TimeDelta with \
                     two years."
                )))?,
        })
    }

    /// Sets the expiration time.
    pub fn with_expires_at(mut self, expires_at: &DateTime<Utc>) -> Self {
        self.expires_at = expires_at.to_owned();
        self
    }
}

impl<Id, AccountId> Passport for Account<Id, AccountId>
where
    Id: std::fmt::Display,
{
    type Id = Id;
    type Group = BasicGroup;
    type Role = BasicRole;

    fn id(&self) -> &Id {
        &self.id
    }

    fn roles(&self) -> &HashSet<BasicRole> {
        &self.roles
    }

    fn groups(&self) -> &HashSet<BasicGroup> {
        &self.groups
    }
}

#[cfg(feature = "storage-seaorm")]
impl TryFrom<crate::storage::sea_orm::models::account::Model> for Account<i32, String> {
    type Error = String;

    fn try_from(
        value: crate::storage::sea_orm::models::account::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            account_id: value.account_id,
            groups: HashSet::<BasicGroup>::from_csv(&value.groups)?,
            roles: HashSet::<BasicRole>::from_csv(&value.roles)?,
            disabled: value.disabled,
            expires_at: value.expires_at,
        })
    }
}
