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
//! # use axum_gate::{permissions::{PermissionChecker, PermissionId}, validate_permissions};
//! # use roaring::RoaringBitmap;
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
//! # use axum_gate::{permissions::{PermissionChecker, PermissionId}, Account};
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
//! # impl axum_gate::utils::AccessHierarchy for MyRole {
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
//! account.grant_permission(PermissionId::from_name("read:resource1"));
//! account.grant_permission(PermissionId::from_name("write:resource1"));
//!
//! // Check if account has permission
//! if PermissionChecker::has_permission(&account.permissions, "read:resource1") {
//!     // Account has permission
//! }
//!
//! // Remove permissions from an account
//! account.revoke_permission(PermissionId::from_name("write:resource1"));
//!
//! // Note: After modifying account permissions, you would typically
//! // save the account back to your storage system using your chosen
//! // storage implementation (see AccountStorageService).
//! ```
//!
//! ## 3. Using Permissions with Gates (recommended)
//!
//! ```rust
//! # use axum_gate::{Account, Gate, Group, permissions::PermissionId};
//! # use axum_gate::jwt::{JsonWebToken, JwtClaims};
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
//! # impl axum_gate::utils::AccessHierarchy for MyRole {
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
//!         Gate::new_cookie("issuer", jwt_codec)
//!             .with_cookie_template(cookie_template)
//!             .grant_permission(PermissionId::from_name("read:resource1"))
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
//! # use axum_gate::permissions::PermissionChecker;
//! # use roaring::RoaringBitmap;
//! # let mut user_permissions = RoaringBitmap::new();
//! # PermissionChecker::grant_permission(&mut user_permissions, "read:resource1");
//! if PermissionChecker::has_permission(&user_permissions, "read:resource1") {
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
//! use axum_gate::permissions::ApplicationValidator;
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
//! use axum_gate::permissions::PermissionCollisionChecker;
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

mod validation;

pub use validation::{
    ApplicationValidator, PermissionCollision, PermissionCollisionChecker, ValidationReport,
};

use std::collections::HashSet;

use anyhow::Result;
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

/// A deterministic permission identifier computed from permission names.
///
/// Permission IDs are generated using SHA-256 hashing of the permission name,
/// ensuring that the same permission name always produces the same ID across
/// all nodes in a distributed system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionId(u32);

impl std::fmt::Display for PermissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PermissionId {
    /// Creates a permission ID from a permission name using deterministic hashing.
    ///
    /// The same permission name will always produce the same ID across all nodes,
    /// enabling zero-synchronization distributed authorization.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum_gate::permissions::PermissionId;
    ///
    /// let read_id = PermissionId::from_name("read:file");
    /// let write_id = PermissionId::from_name("write:file");
    ///
    /// assert_ne!(read_id, write_id);
    /// assert_eq!(read_id, PermissionId::from_name("read:file")); // Deterministic
    /// ```
    pub fn from_name(name: &str) -> Self {
        Self(const_sha256_u32(name))
    }

    /// Returns the underlying u32 value for use in bitmaps.
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Creates a PermissionId from a raw u32 value.
    ///
    /// This should primarily be used for deserialization or when working
    /// with existing bitmap data.
    pub fn from_u32(value: u32) -> Self {
        Self(value)
    }
}

impl From<u32> for PermissionId {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<PermissionId> for u32 {
    fn from(id: PermissionId) -> u32 {
        id.as_u32()
    }
}

/// Zero-synchronization permission checker that works without any coordination
/// between distributed nodes.
pub struct PermissionChecker;

impl PermissionChecker {
    /// Checks if the user has the specified permission.
    ///
    /// This is a pure function that requires no external state or network calls,
    /// making it perfect for distributed systems.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum_gate::permissions::{PermissionChecker, PermissionId};
    /// use roaring::RoaringBitmap;
    ///
    /// let mut user_permissions = RoaringBitmap::new();
    /// user_permissions.insert(PermissionId::from_name("read:file").as_u32());
    ///
    /// assert!(PermissionChecker::has_permission(&user_permissions, "read:file"));
    /// assert!(!PermissionChecker::has_permission(&user_permissions, "write:file"));
    /// ```
    pub fn has_permission(user_permissions: &RoaringBitmap, permission_name: &str) -> bool {
        let permission_id = PermissionId::from_name(permission_name);
        user_permissions.contains(permission_id.as_u32())
    }

    /// Grants a permission to the user's permission bitmap.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum_gate::permissions::{PermissionChecker, PermissionId};
    /// use roaring::RoaringBitmap;
    ///
    /// let mut user_permissions = RoaringBitmap::new();
    /// PermissionChecker::grant_permission(&mut user_permissions, "read:file");
    ///
    /// assert!(PermissionChecker::has_permission(&user_permissions, "read:file"));
    /// ```
    pub fn grant_permission(user_permissions: &mut RoaringBitmap, permission_name: &str) {
        let permission_id = PermissionId::from_name(permission_name);
        user_permissions.insert(permission_id.as_u32());
    }

    /// Revokes a permission from the user's permission bitmap.
    pub fn revoke_permission(user_permissions: &mut RoaringBitmap, permission_name: &str) {
        let permission_id = PermissionId::from_name(permission_name);
        user_permissions.remove(permission_id.as_u32());
    }

    /// Checks if the user has all of the specified permissions.
    pub fn has_all_permissions(
        user_permissions: &RoaringBitmap,
        permission_names: &[&str],
    ) -> bool {
        permission_names
            .iter()
            .all(|name| Self::has_permission(user_permissions, name))
    }

    /// Checks if the user has any of the specified permissions.
    pub fn has_any_permission(user_permissions: &RoaringBitmap, permission_names: &[&str]) -> bool {
        permission_names
            .iter()
            .any(|name| Self::has_permission(user_permissions, name))
    }
}

/// Validates that a set of permission names don't have hash collisions.
///
/// This function should be used in tests or during development to ensure
/// your permission names don't accidentally hash to the same value.
///
/// # Examples
///
/// ```
/// use axum_gate::permissions::validate_permission_uniqueness;
///
/// // This should pass
/// validate_permission_uniqueness(&["read:file", "write:file", "delete:file"]).unwrap();
///
/// // This would panic if there were collisions (very unlikely with SHA-256)
/// ```
pub fn validate_permission_uniqueness(permissions: &[&str]) -> Result<(), String> {
    let mut seen_ids = HashSet::new();
    let mut seen_names = HashSet::new();

    for &permission in permissions {
        // Check for duplicate names
        if !seen_names.insert(permission) {
            return Err(format!("Duplicate permission name: {}", permission));
        }

        // Check for hash collisions
        let id = PermissionId::from_name(permission);
        if let Some(existing) = seen_ids.get(&id) {
            return Err(format!(
                "Hash collision detected between '{}' and '{}' (both hash to {})",
                permission,
                existing,
                id.as_u32()
            ));
        }
        seen_ids.insert(id);
    }

    Ok(())
}

/// Compile-time permission validation macro with detailed error reporting.
///
/// This macro validates that the provided permission names don't have hash collisions
/// and generates a compile error with detailed information if they do.
/// When issues are found, the panic message will include all permissions being validated
/// to help you identify which ones are causing conflicts.
///
/// Note: This macro uses compile-time panics to signal validation failures.
/// For runtime validation with proper error handling, use the validation module.
///
/// # Examples
///
/// ```
/// use axum_gate::validate_permissions;
///
/// validate_permissions![
///     "read:user:profile",
///     "write:user:profile",
///     "delete:user:account",
///     "admin:system:config"
/// ];
/// ```
///
/// If there are issues, the compiler will show the permissions being validated
/// to help you identify duplicates or collisions.
#[macro_export]
macro_rules! validate_permissions {
    ($($perm:literal),* $(,)?) => {
        const _: () = {
            const PERMISSIONS: &[&str] = &[$($perm),*];

            // Validate at compile time
            const fn validate_compile_time() {
                let mut i = 0;
                while i < PERMISSIONS.len() {
                    let mut j = i + 1;
                    while j < PERMISSIONS.len() {
                        // Check for duplicate names
                        if str_eq(PERMISSIONS[i], PERMISSIONS[j]) {
                            panic!(concat!(
                                "Duplicate permission name found in: ",
                                stringify!([$($perm),*]),
                                ". All permission names must be unique. ",
                                "Check for duplicate entries and remove or rename them."
                            ));
                        }

                        // Check for hash collisions
                        let id1 = $crate::permissions::const_sha256_u32(PERMISSIONS[i]);
                        let id2 = $crate::permissions::const_sha256_u32(PERMISSIONS[j]);
                        if id1 == id2 {
                            panic!(concat!(
                                "Hash collision detected in permissions: ",
                                stringify!([$($perm),*]),
                                ". Two different permission strings are hashing to the same u32 value. ",
                                "This is extremely rare with SHA-256, but you need to rename one of the colliding permissions. ",
                                "Look for permissions that might have similar patterns or try adding suffixes to differentiate them."
                            ));
                        }
                        j += 1;
                    }
                    i += 1;
                }
            }

            const fn str_eq(a: &str, b: &str) -> bool {
                if a.len() != b.len() {
                    return false;
                }
                let a_bytes = a.as_bytes();
                let b_bytes = b.as_bytes();
                let mut i = 0;
                while i < a_bytes.len() {
                    if a_bytes[i] != b_bytes[i] {
                        return false;
                    }
                    i += 1;
                }
                true
            }

            validate_compile_time();
        };
    };
}

/// Const-compatible SHA-256 hash function that produces a u32.
///
/// This is a simplified implementation for const contexts. It uses the first
/// 4 bytes of a SHA-256 hash to create a u32 identifier.
/// Computes SHA-256 hash and returns the first 4 bytes as u32.
///
/// Uses the `const-crypto` crate for const-compatible SHA-256 implementation.
pub const fn const_sha256_u32(input: &str) -> u32 {
    let hash = const_crypto::sha2::Sha256::new()
        .update(input.as_bytes())
        .finalize();
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_id_deterministic() {
        let id1 = PermissionId::from_name("read:file");
        let id2 = PermissionId::from_name("read:file");
        assert_eq!(id1, id2);
    }

    #[test]
    fn permission_id_different_names() {
        let read_id = PermissionId::from_name("read:file");
        let write_id = PermissionId::from_name("write:file");
        assert_ne!(read_id, write_id);
    }

    #[test]
    fn permission_checker_basic() {
        let mut permissions = RoaringBitmap::new();

        assert!(!PermissionChecker::has_permission(
            &permissions,
            "read:file"
        ));

        PermissionChecker::grant_permission(&mut permissions, "read:file");
        assert!(PermissionChecker::has_permission(&permissions, "read:file"));
        assert!(!PermissionChecker::has_permission(
            &permissions,
            "write:file"
        ));

        PermissionChecker::revoke_permission(&mut permissions, "read:file");
        assert!(!PermissionChecker::has_permission(
            &permissions,
            "read:file"
        ));
    }

    #[test]
    fn permission_checker_multiple() {
        let mut permissions = RoaringBitmap::new();
        PermissionChecker::grant_permission(&mut permissions, "read:file");
        PermissionChecker::grant_permission(&mut permissions, "write:file");

        assert!(PermissionChecker::has_all_permissions(
            &permissions,
            &["read:file", "write:file"]
        ));
        assert!(!PermissionChecker::has_all_permissions(
            &permissions,
            &["read:file", "delete:file"]
        ));

        assert!(PermissionChecker::has_any_permission(
            &permissions,
            &["read:file", "delete:file"]
        ));
        assert!(!PermissionChecker::has_any_permission(
            &permissions,
            &["delete:file", "admin:system"]
        ));
    }

    #[test]
    fn validate_permission_uniqueness_success() {
        validate_permission_uniqueness(&["read:file", "write:file", "delete:file", "admin:system"])
            .unwrap();
    }

    #[test]
    fn validate_permission_uniqueness_duplicate_name() {
        let result = validate_permission_uniqueness(&[
            "read:file",
            "write:file",
            "read:file", // Duplicate
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate permission name"));
    }

    #[test]
    fn compile_time_validation() {
        validate_permissions![
            "read:user:profile",
            "write:user:profile",
            "delete:user:account",
            "admin:system:config"
        ];
    }
}
