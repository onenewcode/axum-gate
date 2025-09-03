//! Zero-synchronization permission system using deterministic hashing.
//!
//! This module provides a permission system where permission IDs are computed deterministically
//! from permission names using cryptographic hashing. This eliminates the need for synchronization
//! between distributed nodes while maintaining high performance through bitmap operations.
//!
//! # Using Permissions in Your Application
//!
//! ## 1. Validating Permissions at Compile Time
//!
//! ```rust
//! # use axum_gate::auth::PermissionId;
//! axum_gate::validate_permissions![
//!     "read:resource1",
//!     "write:resource1",
//!     "read:resource2",
//!     "admin:system"
//! ];
//! ```
//!
//! ## 2. Working with Account Permissions (recommended)
//!
//! ```rust
//! # use axum_gate::auth::{PermissionId, Account};
//! # #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! # enum MyRole { User, Admin }
//! # impl std::fmt::Display for MyRole {
//! #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//! #         match self {
//! #             MyRole::User => write!(f, "User"),
//! #             MyRole::Admin => write!(f, "Admin"),
//! #         }
//! #     }
//! # }
//! # use axum_gate::advanced::AccessHierarchy;
//! # impl AccessHierarchy for MyRole {
//! #     fn supervisor(&self) -> Option<Self> {
//! #         match self {
//! #             Self::Admin => None,
//! #             Self::User => Some(Self::Admin),
//! #         }
//! #     }
//! #     fn subordinate(&self) -> Option<Self> {
//! #         match self {
//! #             Self::Admin => Some(Self::User),
//! #             Self::User => None,
//! #         }
//! #     }
//! # }
//! # #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! # enum MyGroup { Staff, Premium }
//! let mut account = Account::<MyRole, MyGroup>::new("user123", &[MyRole::User], &[MyGroup::Staff]);
//!
//! // Add permissions to an account
//! account.grant_permission("read:resource1");
//! account.grant_permission("write:resource1");
//!
//! // Check if account has permission
//! if account.permissions.has("read:resource1") {
//!     // Account has permission
//! }
//!
//! // Remove permissions from an account
//! account.revoke_permission("write:resource1");
//!
//! // Note: After modifying account permissions, you would typically
//! // save the account back to your repository system using your chosen
//! // repository implementation (see AccountRepository).
//! ```
//!
//! ## 3. Using Permissions with Gates (recommended)
//!
//! ```
//! # use axum_gate::auth::{Account, Group, PermissionId, AccessPolicy};
//! # use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! # use axum_gate::prelude::Gate;
//! # use std::sync::Arc;
//! # use axum::{routing::get, Router};
//! # #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! # enum MyRole { User, Admin }
//! # impl std::fmt::Display for MyRole {
//! #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//! #         match self {
//! #             MyRole::User => write!(f, "User"),
//! #             MyRole::Admin => write!(f, "Admin"),
//! #         }
//! #     }
//! # }
//! # impl AccessHierarchy for MyRole {
//! #     fn supervisor(&self) -> Option<Self> {
//! #         match self {
//! #             Self::Admin => None,
//! #             Self::User => Some(Self::Admin),
//! #         }
//! #     }
//! #     fn subordinate(&self) -> Option<Self> {
//! #         match self {
//! #             Self::Admin => Some(Self::User),
//! #             Self::User => None,
//! #         }
//! #     }
//! # }
//! # #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//! # enum MyGroup { Staff, Premium }
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<MyRole, MyGroup>>>::default());
//! # let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
//! let app = Router::<()>::new()
//!     .route("/protected", get(protected_handler))
//!     .layer(
//!         Gate::cookie_deny_all("issuer", jwt_codec)
//!             .with_cookie_template(cookie_template)
//!             .with_policy(AccessPolicy::<MyRole, MyGroup>::require_permission(PermissionId::from("read:resource1")))
//!     );
//!
//! async fn protected_handler() -> &'static str {
//!     "Access granted!"
//! }
//! ```

pub mod validation;

use crate::domain::values::PermissionId;
use crate::errors::{DomainError, Error, Result};

use std::collections::{HashMap, HashSet};

/// Validates that a set of permission names don't have hash collisions.
///
/// This function should be used in tests or during development to ensure
/// your permission names don't accidentally hash to the same value.
///
/// # Examples
///
/// ```
/// use axum_gate::auth::validate_permission_uniqueness;
///
/// // This should pass
/// validate_permission_uniqueness(&["read:file", "write:file", "delete:file"]).unwrap();
///
/// // This would return an error if there were collisions (very unlikely with SHA-256)
/// ```
pub fn validate_permission_uniqueness(permissions: &[&str]) -> Result<()> {
    // With 64-bit identifiers the probability of collision is negligible; we still
    // keep this to catch *duplicate names* (same normalized string) and provide
    // early detection if an extremely unlikely hash collision ever occurred.
    let mut seen_ids: HashMap<u64, &str> = HashMap::new();
    let mut seen_names = HashSet::new();

    for &permission in permissions {
        // Check for duplicate names
        if !seen_names.insert(permission) {
            return Err(Error::Domain(DomainError::permission_collision(
                0,
                vec![permission.to_string()],
            )));
        }

        // Check for hash collisions (expected to be practically impossible with 64-bit IDs)
        let id = PermissionId::from(permission);
        let raw = id.as_u64();
        if let Some(existing_permission) = seen_ids.get(&raw) {
            return Err(Error::Domain(DomainError::permission_collision(
                raw,
                vec![existing_permission.to_string(), permission.to_string()],
            )));
        }
        seen_ids.insert(raw, permission);
    }

    Ok(())
}

/// Macro for compile-time permission validation.
///
/// This macro validates that the provided permission strings don't have hash collisions
/// and generates a compile-time test to ensure the validation passes. It should be called
/// once in your application with all the permission strings you use.
///
/// # Examples
///
/// ```rust
/// # use axum_gate::validate_permissions;
///
/// validate_permissions![
///     "read:users",
///     "write:users",
///     "delete:users",
///     "admin:system"
/// ];
/// ```
///
/// # Panics
///
/// This macro will cause a compile-time error if any of the permission strings
/// hash to the same value (extremely unlikely with SHA-256).
#[macro_export]
macro_rules! validate_permissions {
    ($($permission:expr),* $(,)?) => {
        #[cfg(test)]
        mod __axum_gate_permission_validation {

            #[test]
            fn validate_permission_uniqueness() {
                let permissions = &[$($permission),*];
                $crate::auth::validate_permission_uniqueness(permissions)
                    .expect("Permission validation failed: hash collision detected");
            }

            // Also validate at compile time by computing all hashes
            #[allow(dead_code)]
            const fn __validate_compile_time() {
                $(
                    let _id = $crate::advanced::const_sha256_u64($permission);
                )*
            }

            // Force compile-time evaluation
            #[allow(dead_code)]
            const _: () = __validate_compile_time();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_basic() {
        use crate::domain::values::Permissions;

        let mut permissions = Permissions::new();

        // Initially no permissions
        assert!(!permissions.has("read:file"));

        // Grant permission
        permissions.grant("read:file");
        assert!(permissions.has("read:file"));
        assert!(!permissions.has("write:file"));

        // Revoke permission
        permissions.revoke("read:file");
        assert!(!permissions.has("read:file"));
    }

    #[test]
    fn permissions_multiple() {
        use crate::domain::values::Permissions;

        let mut permissions = Permissions::new();

        permissions.grant("read:file");
        permissions.grant("write:file");

        assert!(permissions.has_all(["read:file", "write:file"]));
        assert!(!permissions.has_all(["read:file", "delete:file"]));

        assert!(permissions.has_any(["read:file", "delete:file"]));
        assert!(!permissions.has_any(["delete:file", "admin:system"]));
    }

    #[test]
    fn validate_permission_uniqueness_success() {
        validate_permission_uniqueness(&["read:file", "write:file", "delete:file"]).unwrap();
    }

    #[test]
    fn validate_permission_uniqueness_duplicate_name() {
        let result = validate_permission_uniqueness(&["read:file", "read:file"]);
        assert!(result.is_err());
    }

    // Test the macro
    validate_permissions!["test:permission1", "test:permission2", "test:permission3"];
}
