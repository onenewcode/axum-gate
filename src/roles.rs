//! Default implementation of roles and their relation.

mod role_hierarchy;

pub use self::role_hierarchy::RoleHierarchy;
use serde::{Deserialize, Serialize};

/// Available default roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum BasicRole {
    /// The person having this type is considered an Administrator.
    Admin,
    /// The person having this type is considered a Moderator.
    Moderator,
    /// The person is considered a Reporter.
    Reporter,
    /// The person having this type is considered a User.
    User,
    /// An anonymous user.
    Anonymous,
}

impl Default for BasicRole {
    fn default() -> Self {
        Self::Anonymous
    }
}

impl RoleHierarchy for BasicRole {
    fn subordinate(&self) -> Option<Self> {
        match self {
            Self::Admin => Some(Self::Moderator),
            Self::Moderator => Some(Self::Reporter),
            Self::Reporter => Some(Self::User),
            Self::User => None,
            Self::Anonymous => None,
        }
    }
    fn supervisor(&self) -> Option<Self> {
        match self {
            Self::Admin => None,
            Self::Moderator => Some(Self::Admin),
            Self::Reporter => Some(Self::Moderator),
            Self::User => Some(Self::Reporter),
            Self::Anonymous => None,
        }
    }
}
