//! Zero-synchronization permission system using deterministic hashing.
//!
//! This module provides a permission system where permission IDs are computed deterministically
//! from permission names using cryptographic hashing. This eliminates the need for synchronization
//! between distributed nodes while maintaining high performance through bitmap operations.

use anyhow::Result;
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
    /// use axum_gate::{PermissionChecker, PermissionId};
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
    /// use axum_gate::{PermissionChecker, PermissionId};
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
/// use axum_gate::validate_permission_uniqueness;
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

/// Compile-time permission validation macro.
///
/// This macro validates that the provided permission names don't have hash collisions
/// and generates a compile error if they do.
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
                            panic!("Duplicate permission name found");
                        }

                        // Check for hash collisions
                        let id1 = $crate::const_sha256_u32(PERMISSIONS[i]);
                        let id2 = $crate::const_sha256_u32(PERMISSIONS[j]);
                        if id1 == id2 {
                            panic!("Hash collision detected between permissions");
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
pub const fn const_sha256_u32(input: &str) -> u32 {
    const_sha256_first_u32(input.as_bytes())
}

/// Helper function to compute SHA-256 and return first 4 bytes as u32.
const fn const_sha256_first_u32(input: &[u8]) -> u32 {
    let hash = const_sha256(input);
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// Const-compatible SHA-256 implementation.
///
/// This is a simplified const-compatible version of SHA-256.
/// For production use, consider using a more optimized implementation.
const fn const_sha256(input: &[u8]) -> [u8; 32] {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Initial hash values
    let mut h0 = 0x6a09e667u32;
    let mut h1 = 0xbb67ae85u32;
    let mut h2 = 0x3c6ef372u32;
    let mut h3 = 0xa54ff53au32;
    let mut h4 = 0x510e527fu32;
    let mut h5 = 0x9b05688cu32;
    let mut h6 = 0x1f83d9abu32;
    let mut h7 = 0x5be0cd19u32;

    // Pre-processing: adding a single 1 bit
    let mut padded = [0u8; 64];
    let input_len = input.len();

    // Copy input
    let mut i = 0;
    while i < input_len && i < 55 {
        padded[i] = input[i];
        i += 1;
    }

    // Add the '1' bit (plus zero padding)
    if input_len < 55 {
        padded[input_len] = 0x80;
    }

    // Add length in bits as big-endian 64-bit integer
    let bit_len = (input_len * 8) as u64;
    padded[56] = ((bit_len >> 56) & 0xff) as u8;
    padded[57] = ((bit_len >> 48) & 0xff) as u8;
    padded[58] = ((bit_len >> 40) & 0xff) as u8;
    padded[59] = ((bit_len >> 32) & 0xff) as u8;
    padded[60] = ((bit_len >> 24) & 0xff) as u8;
    padded[61] = ((bit_len >> 16) & 0xff) as u8;
    padded[62] = ((bit_len >> 8) & 0xff) as u8;
    padded[63] = (bit_len & 0xff) as u8;

    // Process the message in 512-bit chunks
    let mut w = [0u32; 64];

    // Copy chunk into first 16 words W[0..15] of the message schedule array
    let mut i = 0;
    while i < 16 {
        w[i] = u32::from_be_bytes([
            padded[i * 4],
            padded[i * 4 + 1],
            padded[i * 4 + 2],
            padded[i * 4 + 3],
        ]);
        i += 1;
    }

    // Extend the first 16 words into the remaining 48 words W[16..63]
    let mut i = 16;
    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }

    // Initialize working variables
    let mut a = h0;
    let mut b = h1;
    let mut c = h2;
    let mut d = h3;
    let mut e = h4;
    let mut f = h5;
    let mut g = h6;
    let mut h = h7;

    // Compression function main loop
    let mut i = 0;
    while i < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);

        i += 1;
    }

    // Add the compressed chunk to the current hash value
    h0 = h0.wrapping_add(a);
    h1 = h1.wrapping_add(b);
    h2 = h2.wrapping_add(c);
    h3 = h3.wrapping_add(d);
    h4 = h4.wrapping_add(e);
    h5 = h5.wrapping_add(f);
    h6 = h6.wrapping_add(g);
    h7 = h7.wrapping_add(h);

    // Produce the final hash value as a 256-bit number
    let mut result = [0u8; 32];

    let h0_bytes = h0.to_be_bytes();
    let h1_bytes = h1.to_be_bytes();
    let h2_bytes = h2.to_be_bytes();
    let h3_bytes = h3.to_be_bytes();
    let h4_bytes = h4.to_be_bytes();
    let h5_bytes = h5.to_be_bytes();
    let h6_bytes = h6.to_be_bytes();
    let h7_bytes = h7.to_be_bytes();

    result[0] = h0_bytes[0];
    result[1] = h0_bytes[1];
    result[2] = h0_bytes[2];
    result[3] = h0_bytes[3];
    result[4] = h1_bytes[0];
    result[5] = h1_bytes[1];
    result[6] = h1_bytes[2];
    result[7] = h1_bytes[3];
    result[8] = h2_bytes[0];
    result[9] = h2_bytes[1];
    result[10] = h2_bytes[2];
    result[11] = h2_bytes[3];
    result[12] = h3_bytes[0];
    result[13] = h3_bytes[1];
    result[14] = h3_bytes[2];
    result[15] = h3_bytes[3];
    result[16] = h4_bytes[0];
    result[17] = h4_bytes[1];
    result[18] = h4_bytes[2];
    result[19] = h4_bytes[3];
    result[20] = h5_bytes[0];
    result[21] = h5_bytes[1];
    result[22] = h5_bytes[2];
    result[23] = h5_bytes[3];
    result[24] = h6_bytes[0];
    result[25] = h6_bytes[1];
    result[26] = h6_bytes[2];
    result[27] = h6_bytes[3];
    result[28] = h7_bytes[0];
    result[29] = h7_bytes[1];
    result[30] = h7_bytes[2];
    result[31] = h7_bytes[3];

    result
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
