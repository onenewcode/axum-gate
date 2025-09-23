use crate::domain::values::{PermissionId, PermissionMapping};
use crate::errors::Result;

use std::future::Future;

/// Repository abstraction for persisting and retrieving [`PermissionMapping`] entities.
///
/// This trait enables the optional registry pattern for permission string mappings,
/// allowing reverse lookup from permission IDs back to their original string
/// representations. This is implemented alongside the existing bitmap-based
/// permission system without replacing it.
///
/// # Purpose
///
/// The permission mapping repository provides optional functionality for:
/// - Debugging and logging with human-readable permission names
/// - Administrative interfaces showing permission details
/// - Audit trails with readable permission descriptions
/// - Permission reporting and analysis
///
/// # Usage Pattern
///
/// This repository is intended to be used optionally alongside the existing
/// `Permissions` struct. When permission strings need to be recoverable:
///
/// ```rust,ignore
/// // Store the mapping when granting permissions
/// let mapping = PermissionMapping::from_string("read:api");
/// permissions.grant(&mapping.normalized_string());
/// repo.store_mapping(mapping).await?;
///
/// // Later, retrieve the original string
/// if let Some(mapping) = repo.query_mapping_by_id(permission_id).await? {
///     println!("Permission: {}", mapping.original_string());
/// }
/// ```
///
/// # Semantics
///
/// | Method                    | Success (`Ok`) Return Value                 | Typical `None` Meaning                    | Error (`Err`) Meaning                      |
/// |---------------------------|---------------------------------------------|-------------------------------------------|--------------------------------------------|
/// | `store_mapping`           | `Some(PermissionMapping)` if stored        | `None` if mapping already exists (no-op) | Persistence / connectivity failure         |
/// | `remove_mapping_by_id`    | `Some(PermissionMapping)` = removed        | `None` = no mapping with that ID         | Backend / IO failure                       |
/// | `remove_mapping_by_string`| `Some(PermissionMapping)` = removed        | `None` = no mapping with that string     | Backend / IO failure                       |
/// | `query_mapping_by_id`     | `Some(PermissionMapping)` = found          | `None` = not found                        | Backend / IO failure                       |
/// | `query_mapping_by_string` | `Some(PermissionMapping)` = found          | `None` = not found                        | Backend / IO failure                       |
/// | `list_all_mappings`       | `Vec<PermissionMapping>` (may be empty)    | N/A (empty vec for no mappings)          | Backend / IO failure                       |
///
/// # Consistency Guarantees
///
/// Implementations SHOULD:
/// - Enforce uniqueness of both permission IDs and normalized strings
/// - Validate mapping consistency before storage (use `PermissionMapping::validate()`)
/// - Handle concurrent access safely
/// - Provide atomic operations where possible
///
/// # Performance Considerations
///
/// Since this is an optional feature for human-readable lookups:
/// - Implementations may prioritize consistency over performance
/// - Caching strategies are encouraged for frequently accessed mappings
/// - Bulk operations are not required but may be added via extension traits
///
/// # Error Handling
///
/// Return `Err` for exceptional backend failures (connectivity, serialization,
/// constraint violations). Use `Ok(None)` for "not found" / "no-op" outcomes.
/// Validation errors should be caught early using `PermissionMapping::validate()`.
///
/// # Example Implementation Patterns
///
/// ```rust,ignore
/// // In your service layer
/// async fn grant_permission_with_registry<R>(
///     permissions: &mut Permissions,
///     registry: &R,
///     permission_str: &str,
/// ) -> Result<()>
/// where
///     R: PermissionMappingRepository,
/// {
///     let mapping = PermissionMapping::from_string(permission_str);
///
///     // Grant the permission (primary operation)
///     permissions.grant(mapping.normalized_string());
///
///     // Store the mapping for reverse lookup (optional)
///     if let Err(e) = registry.store_mapping(mapping).await {
///         // Log but don't fail the permission grant
///         tracing::warn!("Failed to store permission mapping: {}", e);
///     }
///
///     Ok(())
/// }
/// ```
pub trait PermissionMappingRepository {
    /// Store a permission mapping.
    ///
    /// Implementations SHOULD enforce uniqueness of both the permission ID
    /// and the normalized string. If a mapping already exists with the same
    /// ID or normalized string, return `Ok(None)` to indicate no change.
    ///
    /// The mapping will be validated for internal consistency before storage.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if successfully stored
    /// - `Ok(None)` if a mapping already exists (no change made)
    /// - `Err(e)` on backend error or validation failure
    fn store_mapping(
        &self,
        mapping: PermissionMapping,
    ) -> impl Future<Output = Result<Option<PermissionMapping>>>;

    /// Remove a permission mapping by its permission ID.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if the mapping existed and was removed
    /// - `Ok(None)` if no mapping matched the ID
    /// - `Err(e)` on backend error
    fn remove_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> impl Future<Output = Result<Option<PermissionMapping>>>;

    /// Remove a permission mapping by its permission string.
    ///
    /// The string will be normalized before lookup, so this will match
    /// regardless of case or whitespace differences.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if the mapping existed and was removed
    /// - `Ok(None)` if no mapping matched the string
    /// - `Err(e)` on backend error
    fn remove_mapping_by_string(
        &self,
        permission: &str,
    ) -> impl Future<Output = Result<Option<PermissionMapping>>>;

    /// Query a permission mapping by its permission ID.
    ///
    /// This is the primary lookup method for reverse resolution of
    /// permission IDs back to their string representations.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if found
    /// - `Ok(None)` if not found
    /// - `Err(e)` on backend failure
    fn query_mapping_by_id(
        &self,
        id: PermissionId,
    ) -> impl Future<Output = Result<Option<PermissionMapping>>>;

    /// Query a permission mapping by its permission string.
    ///
    /// The string will be normalized before lookup, so this will match
    /// regardless of case or whitespace differences.
    ///
    /// Returns:
    /// - `Ok(Some(mapping))` if found
    /// - `Ok(None)` if not found
    /// - `Err(e)` on backend failure
    fn query_mapping_by_string(
        &self,
        permission: &str,
    ) -> impl Future<Output = Result<Option<PermissionMapping>>>;

    /// List all stored permission mappings.
    ///
    /// This method is useful for administrative interfaces, debugging,
    /// and generating permission reports. For large numbers of mappings,
    /// consider implementing pagination via an extension trait.
    ///
    /// Returns:
    /// - `Ok(mappings)` - Vector of all mappings (empty if none exist)
    /// - `Err(e)` on backend failure
    fn list_all_mappings(&self) -> impl Future<Output = Result<Vec<PermissionMapping>>>;

    /// Check if a mapping exists for the given permission ID.
    ///
    /// This is a convenience method that may be more efficient than
    /// `query_mapping_by_id` when you only need to check existence.
    ///
    /// Returns:
    /// - `Ok(true)` if a mapping exists
    /// - `Ok(false)` if no mapping exists
    /// - `Err(e)` on backend failure
    fn has_mapping_for_id(&self, id: PermissionId) -> impl Future<Output = Result<bool>> {
        async move {
            match self.query_mapping_by_id(id).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// Check if a mapping exists for the given permission string.
    ///
    /// This is a convenience method that may be more efficient than
    /// `query_mapping_by_string` when you only need to check existence.
    ///
    /// Returns:
    /// - `Ok(true)` if a mapping exists
    /// - `Ok(false)` if no mapping exists
    /// - `Err(e)` on backend failure
    fn has_mapping_for_string(&self, permission: &str) -> impl Future<Output = Result<bool>> {
        async move {
            match self.query_mapping_by_string(permission).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }
}

/// Extension trait for bulk operations on permission mappings.
///
/// This trait provides optional bulk operations that may be more efficient
/// for implementations that support batch processing. Implementations are
/// not required to implement this trait unless they want to provide
/// optimized bulk operations.
pub trait PermissionMappingRepositoryBulk: PermissionMappingRepository {
    /// Store multiple permission mappings in a single operation.
    ///
    /// This may be more efficient than multiple individual `store_mapping` calls.
    /// Each mapping is validated before storage.
    ///
    /// Returns:
    /// - `Ok(stored_mappings)` - Vector of successfully stored mappings
    /// - `Err(e)` on backend error
    ///
    /// Note: Some mappings may be skipped if they already exist (similar to
    /// `store_mapping` returning `None`). Only newly stored mappings are returned.
    fn store_mappings(
        &self,
        mappings: Vec<PermissionMapping>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>>>;

    /// Remove multiple permission mappings by their IDs.
    ///
    /// Returns:
    /// - `Ok(removed_mappings)` - Vector of successfully removed mappings
    /// - `Err(e)` on backend error
    ///
    /// Mappings that don't exist are silently ignored.
    fn remove_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>>>;

    /// Query multiple permission mappings by their IDs.
    ///
    /// This may be more efficient than multiple individual `query_mapping_by_id` calls.
    ///
    /// Returns:
    /// - `Ok(mappings)` - Vector of found mappings (may be fewer than requested)
    /// - `Err(e)` on backend error
    ///
    /// The order of returned mappings may not match the order of requested IDs.
    /// Mappings that don't exist are silently omitted from the result.
    fn query_mappings_by_ids(
        &self,
        ids: Vec<PermissionId>,
    ) -> impl Future<Output = Result<Vec<PermissionMapping>>>;
}
