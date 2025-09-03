//! Default role implementation with hierarchical access control.
//!
//! This module provides a pre-defined role system with built-in hierarchy support.
//! You can use these roles directly or create your own custom roles by implementing
//! the `AccessHierarchy` trait.
//!
//! # Using Default Roles
//!
//! ```rust
//! use axum_gate::auth::Role;
//! use axum_gate::advanced::AccessHierarchy;
//!
//! // Roles have a built-in hierarchy: Admin > Moderator > Reporter > User
//! assert_eq!(Role::Admin.subordinate(), Some(Role::Moderator));
//! assert_eq!(Role::User.supervisor(), Some(Role::Reporter));
//!
//! // Use with access policies
//! use axum_gate::auth::{AccessPolicy, Group, Account};
//! use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! use axum_gate::prelude::Gate;
//! use std::sync::Arc;
//!
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User));
//! // This allows User, Reporter, Moderator, and Admin roles
//! ```
//!
//! # Creating Custom Roles
//!
//! For applications with specific role requirements:
//!
//! ```rust
//! use axum_gate::advanced::AccessHierarchy;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
//! enum CustomRole {
//!     SuperAdmin,
//!     Admin,
//!     Manager,
//!     Employee,
//! }
//!
//! impl std::fmt::Display for CustomRole {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         write!(f, "{:?}", self)
//!     }
//! }
//!
//! impl AccessHierarchy for CustomRole {
//!     fn supervisor(&self) -> Option<Self> {
//!         match self {
//!             Self::SuperAdmin => None,
//!             Self::Admin => Some(Self::SuperAdmin),
//!             Self::Manager => Some(Self::Admin),
//!             Self::Employee => Some(Self::Manager),
//!         }
//!     }
//!
//!     fn subordinate(&self) -> Option<Self> {
//!         match self {
//!             Self::SuperAdmin => Some(Self::Admin),
//!             Self::Admin => Some(Self::Manager),
//!             Self::Manager => Some(Self::Employee),
//!             Self::Employee => None,
//!         }
//!     }
//! }
//! ```

use crate::domain::traits::AccessHierarchy;
#[cfg(feature = "storage-seaorm")]
use crate::domain::traits::CommaSeparatedValue;

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
    Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, strum::Display, strum::EnumString,
)]
pub enum Role {
    /// Administrator role with the highest level of access.
    ///
    /// Administrators typically have full system access and can perform
    /// any operation within the application.
    Admin,
    /// Moderator role with elevated privileges for content and user management.
    ///
    /// Moderators can typically manage content, moderate discussions,
    /// and have elevated access to user-facing features.
    Moderator,
    /// Reporter role with read access and reporting capabilities.
    ///
    /// Reporters can typically view system information, generate reports,
    /// and access analytics data.
    Reporter,
    /// Basic user role with standard application access.
    ///
    /// Users have access to core application features but limited
    /// administrative capabilities.
    User,
}

impl AccessHierarchy for Role {
    /// Returns the next role down in the hierarchy, if any.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::auth::Role;
    /// use axum_gate::advanced::AccessHierarchy;
    ///
    /// assert_eq!(Role::Admin.subordinate(), Some(Role::Moderator));
    /// assert_eq!(Role::User.subordinate(), None); // Lowest role
    /// ```
    fn subordinate(&self) -> Option<Self> {
        match self {
            Self::Admin => Some(Self::Moderator),
            Self::Moderator => Some(Self::Reporter),
            Self::Reporter => Some(Self::User),
            Self::User => None,
        }
    }

    /// Returns the next role up in the hierarchy, if any.
    ///
    /// # Example
    /// ```rust
    /// use axum_gate::auth::Role;
    /// use axum_gate::advanced::AccessHierarchy;
    ///
    /// assert_eq!(Role::User.supervisor(), Some(Role::Reporter));
    /// assert_eq!(Role::Admin.supervisor(), None); // Highest role
    /// ```
    fn supervisor(&self) -> Option<Self> {
        match self {
            Self::Admin => None,
            Self::Moderator => Some(Self::Admin),
            Self::Reporter => Some(Self::Moderator),
            Self::User => Some(Self::Reporter),
        }
    }
}

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
