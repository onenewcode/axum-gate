//! Permission mapping domain value for the registry pattern.
//!
//! This module provides a domain value object that represents the mapping
//! between permission strings and their 64-bit IDs, enabling optional
//! reverse lookup capabilities while maintaining the performance benefits
//! of the existing bitmap-based permission system.

use crate::domain::values::PermissionId;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Domain value representing a mapping between permission strings and their IDs.
///
/// This type encapsulates the relationship between:
/// - The original permission string as provided by the user
/// - The normalized permission string (trimmed and lowercased)
/// - The computed 64-bit permission ID used in the bitmap storage
///
/// # Purpose
///
/// This mapping enables reverse lookup from permission IDs back to their
/// original string representations, which is useful for:
/// - Debugging and logging
/// - Administrative interfaces
/// - Audit trails
/// - Permission reporting
///
/// # Design Principles
///
/// - Immutable once created (use builder pattern for modifications)
/// - Contains all necessary information for bidirectional mapping
/// - Validates consistency between string and ID during construction
/// - Provides safe access to both original and normalized forms
///
/// # Examples
///
/// ```rust
/// use axum_gate::auth::{PermissionMapping, PermissionId};
///
/// // Create from a permission string
/// let mapping = PermissionMapping::from_string("Read:API");
/// assert_eq!(mapping.original_string(), "Read:API");
/// assert_eq!(mapping.normalized_string(), "read:api");
/// assert_eq!(mapping.permission_id(), PermissionId::from("Read:API"));
///
/// // Create from components (useful for deserialization)
/// let id = PermissionId::from("write:file");
/// let mapping = PermissionMapping::new("Write:File", "write:file", id)?;
/// ```
///
/// # Validation
///
/// The mapping validates that the provided permission ID actually corresponds
/// to the normalized string to prevent inconsistent state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionMapping {
    /// The original permission string as provided by the user
    original_string: String,
    /// The normalized permission string (trimmed and lowercased)
    normalized_string: String,
    /// The computed 64-bit permission ID
    permission_id: PermissionId,
}

impl PermissionMapping {
    /// Creates a new permission mapping from individual components.
    ///
    /// This constructor validates that the permission ID actually corresponds
    /// to the normalized string to ensure consistency.
    ///
    /// # Arguments
    ///
    /// * `original` - The original permission string as provided
    /// * `normalized` - The normalized permission string (should be trimmed and lowercased)
    /// * `id` - The permission ID that should correspond to the normalized string
    ///
    /// # Returns
    ///
    /// Returns `Ok(PermissionMapping)` if the ID matches the normalized string,
    /// or `Err(PermissionMappingError)` if there's a mismatch.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::auth::{PermissionMapping, PermissionId};
    ///
    /// let id = PermissionId::from("read:api");
    /// let mapping = PermissionMapping::new("Read:API", "read:api", id)?;
    /// assert_eq!(mapping.original_string(), "Read:API");
    /// ```
    pub fn new(
        original: impl Into<String>,
        normalized: impl Into<String>,
        id: PermissionId,
    ) -> Result<Self, PermissionMappingError> {
        let original_string = original.into();
        let normalized_string = normalized.into();

        // Validate that the ID corresponds to the normalized string
        let expected_id = PermissionId::from(normalized_string.as_str());
        if id != expected_id {
            return Err(PermissionMappingError::IdMismatch {
                normalized_string: normalized_string.clone(),
                provided_id: id.as_u64(),
                expected_id: expected_id.as_u64(),
            });
        }

        Ok(Self {
            original_string,
            normalized_string,
            permission_id: id,
        })
    }

    /// Creates a permission mapping from a permission string.
    ///
    /// This is the most common way to create a mapping, automatically
    /// computing the normalized form and permission ID.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission string to create a mapping for
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::auth::PermissionMapping;
    ///
    /// let mapping = PermissionMapping::from_string("  Read:API  ");
    /// assert_eq!(mapping.original_string(), "  Read:API  ");
    /// assert_eq!(mapping.normalized_string(), "read:api");
    /// ```
    pub fn from_string(permission: impl Into<String>) -> Self {
        let original_string = permission.into();
        let normalized_string = normalize_permission(&original_string);
        let permission_id = PermissionId::from(normalized_string.as_str());

        Self {
            original_string,
            normalized_string,
            permission_id,
        }
    }

    /// Returns the original permission string as provided by the user.
    ///
    /// This preserves the exact formatting, case, and whitespace of the
    /// original input, which can be useful for display purposes.
    pub fn original_string(&self) -> &str {
        &self.original_string
    }

    /// Returns the normalized permission string.
    ///
    /// The normalized string has been trimmed of whitespace and converted
    /// to lowercase, and is used for computing the permission ID.
    pub fn normalized_string(&self) -> &str {
        &self.normalized_string
    }

    /// Returns the computed permission ID.
    ///
    /// This is the 64-bit ID that would be stored in the permissions bitmap.
    pub fn permission_id(&self) -> PermissionId {
        self.permission_id
    }

    /// Returns the permission ID as a raw u64 value.
    ///
    /// This is a convenience method for when you need the raw ID value
    /// for storage or comparison purposes.
    pub fn id_as_u64(&self) -> u64 {
        self.permission_id.as_u64()
    }

    /// Checks if this mapping corresponds to the given permission string.
    ///
    /// This compares against the normalized form of the provided string,
    /// so it will match regardless of case or whitespace differences.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::auth::PermissionMapping;
    ///
    /// let mapping = PermissionMapping::from_string("read:api");
    /// assert!(mapping.matches_string("READ:API"));
    /// assert!(mapping.matches_string("  read:api  "));
    /// assert!(!mapping.matches_string("write:api"));
    /// ```
    pub fn matches_string(&self, permission: &str) -> bool {
        let normalized = normalize_permission(permission);
        self.normalized_string == normalized
    }

    /// Checks if this mapping corresponds to the given permission ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_gate::auth::{PermissionMapping, PermissionId};
    ///
    /// let mapping = PermissionMapping::from_string("read:api");
    /// let id = PermissionId::from("read:api");
    /// assert!(mapping.matches_id(id));
    /// ```
    pub fn matches_id(&self, id: PermissionId) -> bool {
        self.permission_id == id
    }

    /// Validates that this mapping is internally consistent.
    ///
    /// This checks that the permission ID actually corresponds to the
    /// normalized string, which should always be true for properly
    /// constructed mappings.
    ///
    /// Returns `Ok(())` if consistent, or `Err(PermissionMappingError)` if not.
    pub fn validate(&self) -> Result<(), PermissionMappingError> {
        let expected_id = PermissionId::from(self.normalized_string.as_str());
        if self.permission_id != expected_id {
            return Err(PermissionMappingError::IdMismatch {
                normalized_string: self.normalized_string.clone(),
                provided_id: self.permission_id.as_u64(),
                expected_id: expected_id.as_u64(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for PermissionMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PermissionMapping(original: '{}', normalized: '{}', id: {})",
            self.original_string,
            self.normalized_string,
            self.permission_id.as_u64()
        )
    }
}

impl From<&str> for PermissionMapping {
    fn from(permission: &str) -> Self {
        Self::from_string(permission)
    }
}

impl From<String> for PermissionMapping {
    fn from(permission: String) -> Self {
        Self::from_string(permission)
    }
}

impl From<PermissionId> for PermissionMapping {
    fn from(id: PermissionId) -> Self {
        // Note: We can't recover the original string from just the ID,
        // so we use a placeholder that indicates this limitation
        let placeholder = format!("<unknown-original:{}>", id.as_u64());

        // We also can't recover the exact normalized string, but we can
        // indicate that this mapping was created from an ID
        let normalized_placeholder = format!("<id-only:{}>", id.as_u64());

        Self {
            original_string: placeholder,
            normalized_string: normalized_placeholder,
            permission_id: id,
        }
    }
}

/// Errors that can occur when working with permission mappings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionMappingError {
    /// The provided permission ID doesn't match the normalized string.
    #[error(
        "Permission ID mismatch: normalized string '{normalized_string}' should produce ID {expected_id}, but got {provided_id}"
    )]
    IdMismatch {
        /// The normalized permission string that was used for ID computation
        normalized_string: String,
        /// The permission ID that was provided
        provided_id: u64,
        /// The permission ID that should have been computed from the normalized string
        expected_id: u64,
    },
}

/// Normalize a permission name (trim + lowercase).
///
/// This function implements the same normalization logic used in
/// the PermissionId implementation to ensure consistency.
fn normalize_permission(input: &str) -> String {
    input.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_creates_valid_mapping() {
        let mapping = PermissionMapping::from_string("Read:API");
        assert_eq!(mapping.original_string(), "Read:API");
        assert_eq!(mapping.normalized_string(), "read:api");
        assert_eq!(mapping.permission_id(), PermissionId::from("read:api"));
    }

    #[test]
    fn from_string_handles_whitespace() {
        let mapping = PermissionMapping::from_string("  Write:File  ");
        assert_eq!(mapping.original_string(), "  Write:File  ");
        assert_eq!(mapping.normalized_string(), "write:file");
    }

    #[test]
    fn new_validates_consistency() {
        let id = PermissionId::from("read:api");
        let mapping = PermissionMapping::new("Read:API", "read:api", id);
        assert!(mapping.is_ok());
    }

    #[test]
    fn new_rejects_inconsistent_id() {
        let id = PermissionId::from("write:api");
        let result = PermissionMapping::new("Read:API", "read:api", id);
        assert!(result.is_err());

        if let Err(PermissionMappingError::IdMismatch {
            normalized_string,
            provided_id,
            expected_id,
        }) = result
        {
            assert_eq!(normalized_string, "read:api");
            assert_eq!(provided_id, PermissionId::from("write:api").as_u64());
            assert_eq!(expected_id, PermissionId::from("read:api").as_u64());
        }
    }

    #[test]
    fn matches_string_works_with_normalization() {
        let mapping = PermissionMapping::from_string("read:api");
        assert!(mapping.matches_string("READ:API"));
        assert!(mapping.matches_string("  read:api  "));
        assert!(mapping.matches_string("Read:Api"));
        assert!(!mapping.matches_string("write:api"));
    }

    #[test]
    fn matches_id_works_correctly() {
        let mapping = PermissionMapping::from_string("read:api");
        let matching_id = PermissionId::from("read:api");
        let different_id = PermissionId::from("write:api");

        assert!(mapping.matches_id(matching_id));
        assert!(!mapping.matches_id(different_id));
    }

    #[test]
    fn validate_passes_for_consistent_mapping() {
        let mapping = PermissionMapping::from_string("read:api");
        assert!(mapping.validate().is_ok());
    }

    #[test]
    fn from_permission_id_creates_placeholder_mapping() {
        let id = PermissionId::from("test:permission");
        let mapping = PermissionMapping::from(id);

        assert!(mapping.original_string().contains("unknown-original"));
        assert!(mapping.normalized_string().contains("id-only"));
        assert_eq!(mapping.permission_id(), id);
    }

    #[test]
    fn display_shows_all_components() {
        let mapping = PermissionMapping::from_string("Read:API");
        let display = format!("{}", mapping);

        assert!(display.contains("Read:API"));
        assert!(display.contains("read:api"));
        assert!(display.contains(&mapping.id_as_u64().to_string()));
    }

    #[test]
    fn mapping_equality_works() {
        let mapping1 = PermissionMapping::from_string("read:api");
        let mapping2 = PermissionMapping::from_string("READ:API");

        // These should be equal because they have the same normalized form
        assert_eq!(mapping1.normalized_string(), mapping2.normalized_string());
        assert_eq!(mapping1.permission_id(), mapping2.permission_id());

        // But they're not equal as mappings because the original strings differ
        assert_ne!(mapping1, mapping2);
    }

    #[test]
    fn id_as_u64_convenience_method() {
        let mapping = PermissionMapping::from_string("read:api");
        assert_eq!(mapping.id_as_u64(), mapping.permission_id().as_u64());
    }

    #[test]
    fn from_traits_work() {
        let from_str: PermissionMapping = "read:api".into();
        let from_string: PermissionMapping = "read:api".to_string().into();

        assert_eq!(from_str.normalized_string(), "read:api");
        assert_eq!(from_string.normalized_string(), "read:api");
    }
}
