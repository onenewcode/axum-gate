//! Group entity for organizing users into collections.
//!
//! Groups provide a way to organize users into logical collections for access control.
//! Unlike roles, groups are typically used for organizational purposes like departments,
//! teams, or project memberships.
//!
//! # Creating and Using Groups
//!
//! ```rust
//! use axum_gate::auth::{Group, AccessPolicy, Role};
//!
//! // Create groups
//! let engineering = Group::new("engineering");
//! let marketing = Group::new("marketing");
//! let backend_team = Group::new("backend-team");
//!
//! // Use groups in access policies
//! let policy = AccessPolicy::<Role, Group>::require_group(engineering)
//!     .or_require_group(marketing);
//! ```
//!
//! # Group-Based Access Control
//!
//! ```rust
//! use axum_gate::auth::{Account, Role, Group, AccessPolicy};
//! use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! use axum_gate::prelude::Gate;
//! use std::sync::Arc;
//!
//! // Create an account with group membership
//! let account = Account::new(
//!     "developer@example.com",
//!     &[Role::User],
//!     &[Group::new("engineering"), Group::new("backend-team")]
//! );
//!
//! // Create access policy for specific groups
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(
//!         AccessPolicy::<Role, Group>::require_group(Group::new("engineering"))
//!             .or_require_group(Group::new("qa-team"))
//!     );
//! ```

#[cfg(feature = "storage-seaorm")]
use crate::domain::traits::CommaSeparatedValue;

use serde::{Deserialize, Serialize};

/// A group represents a collection of users for access control purposes.
///
/// Groups are typically used to represent organizational units like departments,
/// teams, projects, or any other logical grouping of users. They provide an
/// additional dimension of access control beyond roles.
///
/// # Example Usage
/// ```rust
/// use axum_gate::auth::Group;
///
/// let engineering = Group::new("engineering");
/// let backend_team = Group::new("backend-team");
/// let project_alpha = Group::new("project-alpha");
///
/// println!("Group name: {}", engineering.name());
/// ```
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct Group(String);

impl Group {
    /// Creates a new group with the specified name.
    ///
    /// # Arguments
    /// * `group` - The name of the group (e.g., "engineering", "marketing", "admin")
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::auth::Group;
    ///
    /// let engineering = Group::new("engineering");
    /// let marketing = Group::new("marketing");
    /// let project_team = Group::new("project-alpha-team");
    /// ```
    pub fn new(group: &str) -> Self {
        Self(group.to_string())
    }

    /// Returns the name of this group.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::auth::Group;
    ///
    /// let group = Group::new("engineering");
    /// assert_eq!(group.name(), "engineering");
    /// ```
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "storage-seaorm")]
impl CommaSeparatedValue for Vec<Group> {
    fn from_csv(value: &str) -> Result<Self, String> {
        Ok(value
            .split(',')
            .collect::<Vec<&str>>()
            .iter()
            .map(|g| Group::new(g))
            .collect())
    }

    fn into_csv(self) -> String {
        self.into_iter()
            .map(|g| g.name().to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}
