//! Permission ID value object for deterministic permission identification.
//!
//! This module provides the `PermissionId` type, which creates deterministic identifiers
//! from permission names using cryptographic hashing. This enables zero-synchronization
//! distributed authorization by ensuring the same permission name always produces the
//! same ID across all nodes.

use const_crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};

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
/// let read_id = PermissionId::from_name("read:file");
/// let write_id = PermissionId::from_name("write:file");
///
/// assert_ne!(read_id, write_id);
/// assert_eq!(read_id, PermissionId::from_name("read:file")); // Deterministic
/// ```
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
    /// use axum_gate::PermissionId;
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

impl From<&str> for PermissionId {
    fn from(name: &str) -> Self {
        Self::from_name(name)
    }
}

impl From<String> for PermissionId {
    fn from(name: String) -> Self {
        Self::from_name(&name)
    }
}

/// Computes a deterministic u32 hash from a string using SHA-256.
///
/// This function is used internally by `PermissionId::from_name` to create
/// consistent identifiers from permission names.
pub const fn const_sha256_u32(input: &str) -> u32 {
    let hash = Sha256::new().update(input.as_bytes()).finalize();
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
    fn permission_id_conversions() {
        let id = PermissionId::from_name("test:permission");
        let u32_val = id.as_u32();
        let from_u32 = PermissionId::from_u32(u32_val);
        assert_eq!(id, from_u32);
    }

    #[test]
    fn permission_id_from_string_types() {
        let name = "test:permission";
        let string_name = name.to_string();

        let from_str = PermissionId::from_name(name);
        let from_str_ref: PermissionId = name.into();
        let from_string: PermissionId = string_name.into();

        assert_eq!(from_str, from_str_ref);
        assert_eq!(from_str, from_string);
    }
}
