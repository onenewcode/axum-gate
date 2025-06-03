//! Default implementation of roles and their relation.

use crate::utils::AccessHierarchy;
use serde::{Deserialize, Serialize};

/// Available default roles.
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, strum::Display, strum::EnumString,
)]
pub enum Role {
    /// The person having this type is considered an Administrator.
    Admin,
    /// The person having this type is considered a Moderator.
    Moderator,
    /// The person is considered a Reporter.
    Reporter,
    /// The person having this type is considered a User.
    User,
}

impl AccessHierarchy for Role {
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
