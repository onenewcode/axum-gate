//! Authorization system for role-based, group-based, and permission-based access control.
//!
//! This module provides the core authorization framework for axum-gate, including:
//! - [`AccessPolicy`] - Define who can access protected resources
//! - [`AccessHierarchy`] - Support for hierarchical role systems
//! - [`AuthorizationService`] - Evaluate access policies against user accounts
//!
//! # Quick Start
//!
//! ```rust
//! use axum_gate::authz::{AccessPolicy, AuthorizationService};
//! use axum_gate::accounts::Account;
//! use axum_gate::prelude::{Role, Group};
//! use axum_gate::permissions::PermissionId;
//!
//! // Create access policies
//! let admin_policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
//! let staff_policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_role(Role::Moderator);
//! let group_policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"));
//! let permission_policy = AccessPolicy::<Role, Group>::require_permission(
//!     PermissionId::from("read:api")
//! );
//!
//! // Create user account
//! let account = Account::new("user@example.com", &[Role::User], &[Group::new("engineering")]);
//!
//! // Check authorization
//! let auth_service = AuthorizationService::new(admin_policy.clone());
//! let result = auth_service.is_authorized(&account);
//! ```
//!
//! # Policy Combinations
//!
//! Access policies can be combined using `or_*` methods to create flexible access rules:
//!
//! ```rust
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::prelude::{Role, Group};
//! use axum_gate::permissions::PermissionId;
//!
//! let complex_policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!     .or_require_group(Group::new("security-team"))
//!     .or_require_permission(PermissionId::from("emergency:access"));
//! ```
//!
//! # Hierarchical Roles
//!
//! Use `require_role_or_supervisor` for hierarchical access where higher roles
//! inherit access from lower roles:
//!
//! ```rust
//! use axum_gate::authz::AccessPolicy;
//! use axum_gate::prelude::{Role, Group};
//!
//! // Allows User role and all supervisor roles (Reporter, Moderator, Admin)
//! let hierarchical_policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
//! ```

mod access_hierarchy;
mod access_policy;
mod access_scope;
mod authorization_service;

pub use access_hierarchy::AccessHierarchy;
pub use access_policy::AccessPolicy;
pub use access_scope::AccessScope;
pub use authorization_service::AuthorizationService;
pub mod errors;
pub use errors::AuthzError;
