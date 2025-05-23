//! Default implementation of roles and their relation.

use crate::{AccessHierarchy, CommaSeparatedValue};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

/// Available default roles.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    Hash,
    strum::EnumString,
    strum::Display,
)]
pub enum BasicRole {
    /// The person having this type is considered an Administrator.
    Admin,
    /// The person having this type is considered a Moderator.
    Moderator,
    /// The person is considered a Reporter.
    Reporter,
    /// The person having this type is considered a User.
    User,
}

impl AccessHierarchy for BasicRole {
    fn subordinate(&self) -> Option<Self> {
        match self {
            Self::Admin => Some(Self::Moderator),
            Self::Moderator => Some(Self::Reporter),
            Self::Reporter => Some(Self::User),
            Self::User => None,
        }
    }
    fn supervisor(&self) -> Option<Self> {
        match self {
            Self::Admin => None,
            Self::Moderator => Some(Self::Admin),
            Self::Reporter => Some(Self::Moderator),
            Self::User => Some(Self::Reporter),
        }
    }
}

impl CommaSeparatedValue for HashSet<BasicRole> {
    fn from_csv(value: &str) -> Result<Self, String> {
        let value = value.split(',').collect::<Vec<&str>>();
        let mut result = HashSet::new();
        for v in value {
            result.insert(BasicRole::from_str(v).map_err(|e| e.to_string())?);
        }
        Ok(result)
    }

    fn into_csv(self) -> String {
        self.into_iter()
            .map(|g| g.to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}
