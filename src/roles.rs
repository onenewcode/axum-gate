//! Default role implementation with hierarchical access control.
//!
//! This module provides a pre-defined role system using an ordering-based
//! hierarchy.
//!
//! The ordering is encoded directly by the enum variant order:
//! Higher privilege > Lower privilege
//!
//! Admin > Moderator > Reporter > User
//!
//! # Using Default Roles
//!
//! ```rust
//! use axum_gate::auth::Role;
//!
//! // Ordering (higher privilege comes first):
//! assert!(Role::Admin > Role::Moderator);
//! assert!(Role::Moderator > Role::User);
//!
//! // Use with access policies
//! use axum_gate::auth::{AccessPolicy, Group, Account};
//! use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! use axum_gate::prelude::Gate;
//! use std::sync::Arc;
//!
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User));
//! // This allows User, Reporter, Moderator, and Admin roles (User is the baseline)
//! ```
//!
//! # Creating Custom Roles
//!
//! Implement a custom ordered hierarchy by deriving `Ord` / `PartialOrd` and
//! implementing `Default` for the least-privileged (baseline) variant:
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//! use axum_gate::advanced::AccessHierarchy;
//!
//! #[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
//! enum CustomRole {
//!     #[default]
//!     Employee,
//!     Manager,
//!     Admin,
//!     SuperAdmin,
//! }
//!
//! impl AccessHierarchy for CustomRole {}
//! ```

use crate::authz::AccessHierarchy;
#[cfg(feature = "storage-seaorm")]
use crate::comma_separated_value::CommaSeparatedValue;

#[cfg(feature = "storage-seaorm")]
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Pre-defined roles with hierarchical access control.
///
/// These roles are arranged in a hierarchy where higher roles automatically
/// inherit access from lower roles when using `AccessPolicy::require_role_or_supervisor()`.
///
/// **Hierarchy (highest to lowest):**
/// - `Admin` - Full system access
/// - `Moderator` - Content moderation and user management
/// - `Reporter` - Read access with reporting capabilities
/// - `User` - Basic user access
///
/// # Example Usage
/// ```rust
/// use axum_gate::auth::{Role, AccessPolicy, Group};
///
/// // Grant access to Moderators and all supervisor roles (Admin)
/// let policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::Moderator);
///
/// // Grant access to specific roles only
/// let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
///     .or_require_role(Role::Moderator);
/// ```
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
)]
pub enum Role {
    /// Basic user role with standard application access.
    ///
    /// Users have access to core application features but limited
    /// administrative capabilities.
    #[default]
    User,
    /// Reporter role with read access and reporting capabilities.
    ///
    /// Reporters can typically view system information, generate reports,
    /// and access analytics data.
    Reporter,
    /// Moderator role with elevated privileges for content and user management.
    ///
    /// Moderators can typically manage content, moderate discussions,
    /// and have elevated access to user-facing features.
    Moderator,
    /// Administrator role with the highest level of access.
    ///
    /// Administrators typically have full system access and can perform
    /// any operation within the application.
    Admin,
}

impl AccessHierarchy for Role {}

#[cfg(feature = "storage-seaorm")]
impl CommaSeparatedValue for Vec<Role> {
    fn from_csv(value: &str) -> Result<Self, String> {
        let mut role_str = value.split(',').collect::<Vec<&str>>();
        let mut roles = Vec::with_capacity(role_str.len());
        while let Some(r) = role_str.pop() {
            roles.push(Role::from_str(r).map_err(|e| e.to_string())?);
        }
        Ok(roles)
    }

    fn into_csv(self) -> String {
        self.into_iter()
            .map(|g| g.to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}
