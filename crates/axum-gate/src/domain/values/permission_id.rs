//! Permission ID value object for deterministic permission identification.
//!
//! This module provides the `PermissionId` type, which creates deterministic identifiers
//! from permission names using cryptographic hashing. This enables zero-synchronization
//! distributed authorization by ensuring the same permission name always produces the
//! same ID across all nodes.

use const_crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Trait for types that can be converted to permission names.
///
/// This trait allows permission enums to define their string representation
/// for use with PermissionId. Typically implemented by nested permission enums
/// that provide structured permission definitions.
pub trait AsPermissionName {
    /// Convert the permission to its string representation.
    fn as_permission_name(&self) -> String;
}

/// A deterministic permission identifier computed from permission names.
///
/// `PermissionId` uses SHA-256 hashing to create consistent, collision-resistant identifiers
/// from permission name strings. This design enables distributed systems to work with
/// permissions without requiring synchronization between nodes.
///
/// # Examples
///
/// ```rust
/// use axum_gate::PermissionId;
///
/// let read_id = PermissionId::from("read:file");
/// let write_id = PermissionId::from("write:file");
///
/// assert_ne!(read_id, write_id);
/// assert_eq!(read_id, PermissionId::from("read:file")); // Deterministic
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionId(u32);

impl std::fmt::Display for PermissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PermissionId {
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

impl From<&str> for PermissionId {
    fn from(name: &str) -> Self {
        Self(const_sha256_u32(name))
    }
}

impl From<String> for PermissionId {
    fn from(name: String) -> Self {
        Self::from(name.as_str())
    }
}

impl<T: AsPermissionName> From<&T> for PermissionId {
    fn from(permission: &T) -> Self {
        Self::from(permission.as_permission_name().as_str())
    }
}

/// Computes a deterministic u32 hash from a string using SHA-256.
///
/// This function is used internally by `PermissionId::from` to create
/// consistent identifiers from permission names.
pub const fn const_sha256_u32(input: &str) -> u32 {
    let hash = Sha256::new().update(input.as_bytes()).finalize();
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_id_different_names() {
        let read_id = PermissionId::from("read:file");
        let write_id = PermissionId::from("write:file");
        assert_ne!(read_id, write_id);
    }

    #[test]
    fn permission_id_conversions() {
        let id = PermissionId::from("test:permission");
        let u32_val = id.as_u32();
        let from_u32 = PermissionId::from_u32(u32_val);
        assert_eq!(id, from_u32);
    }

    #[test]
    fn permission_id_from_string_types() {
        let name = "test:permission";
        let string_name = name.to_string();

        let from_str = PermissionId::from(name);
        let from_str_ref: PermissionId = name.into();
        let from_string: PermissionId = string_name.into();

        assert_eq!(from_str, from_str_ref);
        assert_eq!(from_str, from_string);
    }

    #[test]
    fn permission_id_from_permission_trait() {
        #[derive(Debug)]
        enum TestPermission {
            Read,
            Write,
        }

        impl AsPermissionName for TestPermission {
            fn as_permission_name(&self) -> String {
                format!("test:{:?}", self).to_lowercase()
            }
        }

        let read_perm = TestPermission::Read;
        let write_perm = TestPermission::Write;

        let read_id = PermissionId::from(&read_perm);
        let write_id = PermissionId::from(&write_perm);
        let read_id_from_trait = PermissionId::from(&read_perm);

        assert_ne!(read_id, write_id);
        assert_eq!(read_id, read_id_from_trait);
        assert_eq!(read_id, PermissionId::from("test:read"));
        assert_eq!(write_id, PermissionId::from("test:write"));
    }

    #[test]
    fn permission_id_deterministic() {
        let id1 = PermissionId::from("read:file");
        let id2 = PermissionId::from("read:file");
        assert_eq!(id1, id2);
    }

    #[test]
    fn permission_id_nested_enum_example() {
        #[derive(Debug)]
        enum AppPermission {
            Repository(RepositoryPermission),
            Api(ApiPermission),
        }

        #[derive(Debug)]
        enum RepositoryPermission {
            Read,
        }

        #[derive(Debug)]
        enum ApiPermission {
            Read,
        }

        impl AsPermissionName for AppPermission {
            fn as_permission_name(&self) -> String {
                match self {
                    AppPermission::Repository(perm) => {
                        format!("repository:{:?}", perm).to_lowercase()
                    }
                    AppPermission::Api(perm) => format!("api:{:?}", perm).to_lowercase(),
                }
            }
        }

        let repo_read = AppPermission::Repository(RepositoryPermission::Read);
        let api_read = AppPermission::Api(ApiPermission::Read);

        let repo_read_id = PermissionId::from(&repo_read);
        let api_read_id = PermissionId::from(&api_read);

        assert_ne!(repo_read_id, api_read_id);
        assert_eq!(repo_read_id, PermissionId::from("repository:read"));
        assert_eq!(api_read_id, PermissionId::from("api:read"));
    }

    #[test]
    fn permission_id_integrates_with_permissions_struct() {
        use crate::domain::values::Permissions;

        #[derive(Debug)]
        enum TestPermission {
            Read,
            Write,
        }

        impl AsPermissionName for TestPermission {
            fn as_permission_name(&self) -> String {
                format!("test:{:?}", self).to_lowercase()
            }
        }

        let read_perm = TestPermission::Read;
        let write_perm = TestPermission::Write;

        let mut permissions = Permissions::new();

        // Test granting permissions using the new From trait
        permissions.grant(&read_perm); // Uses From<&T> for PermissionId
        permissions.grant(&write_perm);

        // Test checking permissions using the new From trait
        assert!(permissions.has(&read_perm)); // Uses From<&T> for PermissionId
        assert!(permissions.has(&write_perm));

        // Verify it works with string equivalents too
        assert!(permissions.has("test:read"));
        assert!(permissions.has("test:write"));

        // Test with collections
        assert!(permissions.has_all([&read_perm, &write_perm]));
        assert!(permissions.has_any([&read_perm]));
    }
}
