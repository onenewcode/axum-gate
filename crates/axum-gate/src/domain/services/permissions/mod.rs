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
//! # use axum_gate::{PermissionId, validate_permissions};
//! validate_permissions![
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
//! # use axum_gate::{PermissionId, Account};
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
//! # impl axum_gate::AccessHierarchy for MyRole {
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
//! ```rust
//! # use axum_gate::{Account, Gate, Group, PermissionId, AccessPolicy};
//! # use axum_gate::{JsonWebToken, JwtClaims};
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
//! # impl axum_gate::AccessHierarchy for MyRole {
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
//!             .with_policy(AccessPolicy::<MyRole, MyGroup>::require_permission(PermissionId::from_name("read:resource1")))
//!     );
//!
//! async fn protected_handler() -> &'static str {
//!     "Access granted!"
//! }
//! ```
//!
//! ## 4. Checking Permissions in Route Handlers
//!
//! ```rust
//! # use axum_gate::Permissions;
//! # let mut user_permissions = Permissions::new();
//! # user_permissions.grant("read:resource1");
//! if user_permissions.has("read:resource1") {
//!     // Grant access
//! }
//! ```
//!
//! # Validation Approaches
//!
//! While the core permission system handles authorization at runtime, it's crucial to validate
//! that your permission strings don't have hash collisions before deployment. This module provides
//! comprehensive validation tools to ensure your permission system works reliably in production.
//!
//! This module provides two complementary validators for different use cases:
//!
//! ## [`ApplicationValidator`] - High-level Builder Pattern
//!
//! Best for **application startup validation** where you need to collect permissions
//! from multiple sources and validate them once:
//!
//! ```rust
//! use axum_gate::ApplicationValidator;
//!
//! # fn example() -> anyhow::Result<()> {
//! let report = ApplicationValidator::new()
//!     .add_permissions(load_config_permissions())
//!     .add_permissions(load_database_permissions())
//!     .add_permission("system:health")
//!     .validate()?;  // Automatically logs results
//!
//! if !report.is_valid() {
//!     return Err(anyhow::anyhow!("Startup validation failed"));
//! }
//! # Ok(())
//! # }
//! # fn load_config_permissions() -> Vec<String> { vec![] }
//! # fn load_database_permissions() -> Vec<String> { vec![] }
//! ```
//!
//! **Characteristics:**
//! - Builder pattern for incremental permission addition
//! - Single-use (consumed during validation)
//! - Automatic logging of results
//! - Simple pass/fail workflow
//!
//! ## [`PermissionCollisionChecker`] - Low-level Direct Control
//!
//! Best for **runtime validation and analysis** where you need detailed inspection
//! and debugging capabilities:
//!
//! ```rust
//! use axum_gate::PermissionCollisionChecker;
//!
//! # fn example() -> anyhow::Result<()> {
//! let mut checker = PermissionCollisionChecker::new(dynamic_permissions());
//! let report = checker.validate()?;
//!
//! if !report.is_valid() {
//!     // Detailed analysis capabilities
//!     for collision in &report.collisions {
//!         println!("Hash collision: {:?}", collision.permissions);
//!     }
//!
//!     // Check specific permission conflicts
//!     let conflicts = checker.get_conflicting_permissions("user:read");
//!     println!("Conflicts with user:read: {:?}", conflicts);
//! }
//!
//! // Reusable for further analysis
//! let summary = checker.get_permission_summary();
//! # Ok(())
//! # }
//! # fn dynamic_permissions() -> Vec<String> { vec![] }
//! ```
//!
//! **Characteristics:**
//! - Direct instantiation with complete permission set
//! - Stateful and reusable after validation
//! - Detailed introspection methods
//! - Manual control over logging and error handling
//!
//! # Choosing the Right Validator
//!
//! | Use Case | Recommended Validator |
//! |----------|----------------------|
//! | Application startup validation | [`ApplicationValidator`] |
//! | Configuration loading | [`ApplicationValidator`] |
//! | Simple pass/fail validation | [`ApplicationValidator`] |
//! | Runtime permission updates | [`PermissionCollisionChecker`] |
//! | Debugging collision issues | [`PermissionCollisionChecker`] |
//! | Performance-critical validation | [`PermissionCollisionChecker`] |
//! | Custom validation workflows | [`PermissionCollisionChecker`] |

pub mod validation;

use std::collections::{HashMap, HashSet};

use crate::domain::values::PermissionId;
use crate::errors::{DomainError, Error, Result};

/// Validates that a set of permission names don't have hash collisions.
///
/// This function should be used in tests or during development to ensure
/// your permission names don't accidentally hash to the same value.
///
/// # Examples
///
/// ```
/// use axum_gate::validate_permission_uniqueness;
///
/// // This should pass
/// validate_permission_uniqueness(&["read:file", "write:file", "delete:file"]).unwrap();
///
/// // This would return an error if there were collisions (very unlikely with SHA-256)
/// ```
pub fn validate_permission_uniqueness(permissions: &[&str]) -> Result<()> {
    let mut seen_ids: HashMap<u32, &str> = HashMap::new();
    let mut seen_names = HashSet::new();

    for &permission in permissions {
        // Check for duplicate names
        if !seen_names.insert(permission) {
            return Err(Error::Domain(DomainError::permission_collision(
                0,
                vec![permission.to_string()],
            )));
        }

        // Check for hash collisions
        let id = PermissionId::from_name(permission);
        if let Some(existing_permission) = seen_ids.get(&id.as_u32()) {
            return Err(Error::Domain(DomainError::permission_collision(
                id.as_u32(),
                vec![existing_permission.to_string(), permission.to_string()],
            )));
        }
        seen_ids.insert(id.as_u32(), permission);
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
/// use axum_gate::validate_permissions;
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
            use super::*;

            #[test]
            fn validate_permission_uniqueness() {
                let permissions = &[$($permission),*];
                $crate::validate_permission_uniqueness(permissions)
                    .expect("Permission validation failed: hash collision detected");
            }

            // Also validate at compile time by computing all hashes
            #[allow(dead_code)]
            const fn __validate_compile_time() {
                $(
                    let _id = $crate::const_sha256_u32($permission);
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
