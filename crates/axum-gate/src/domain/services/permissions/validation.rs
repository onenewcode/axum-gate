//! Validation utilities for permission collision checking.
//!
//! This module provides runtime validation capabilities for permission strings,
//! complementing the compile-time validation provided by the `validate_permissions!` macro.
//! It's particularly useful when dealing with dynamic permission strings loaded from
//! configuration files, databases, or other runtime sources.
use crate::domain::services::permissions::PermissionId;
use crate::errors::{DomainError, Error, Result};
use std::collections::HashMap;
use tracing::{info, warn};

/// Low-level permission collision checker for runtime validation and analysis.
///
/// This checker validates permission strings for duplicates and hash collisions,
/// providing detailed reports about any issues found. Unlike the compile-time
/// validation, this can handle dynamic permission strings.
///
/// ## Use Cases
///
/// - **Runtime validation**: When permissions change during application lifecycle
/// - **Debugging and analysis**: Need to inspect collision maps and conflicts
/// - **Custom validation workflows**: Require fine-grained control over validation process
/// - **Performance-critical paths**: Direct validation without builder overhead
///
/// ## Compared to ApplicationValidator
///
/// - **State**: Stateful - maintains collision map for post-validation analysis
/// - **Usage**: Direct instantiation with complete permission set
/// - **Methods**: Provides introspection methods like `get_conflicting_permissions()`
/// - **Lifecycle**: Can be reused after validation for analysis
///
/// For simple application startup validation, consider using [`ApplicationValidator`]
/// which provides a more ergonomic builder pattern API.
///
/// # See Also
///
/// - [`ApplicationValidator`] - High-level builder pattern validator for startup validation
///
/// # Examples
///
/// ## Basic validation with post-analysis
///
/// ```
/// use axum_gate::PermissionCollisionChecker;
///
/// let permissions = vec![
///     "user:read".to_string(),
///     "user:write".to_string(),
///     "admin:full_access".to_string(),
/// ];
///
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let report = checker.validate()?;
///
/// if report.is_valid() {
///     println!("All permissions are valid!");
///     // Can still use checker for analysis after validation
///     println!("Total permissions: {}", checker.permission_count());
///     println!("Unique IDs: {}", checker.unique_id_count());
/// } else {
///     println!("Issues found: {}", report.summary());
///     // Check for specific conflicts
///     let conflicts = checker.get_conflicting_permissions("user:read");
///     if !conflicts.is_empty() {
///         println!("Conflicts with user:read: {:?}", conflicts);
///     }
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
///
/// ## Runtime permission updates
///
/// ```
/// use axum_gate::PermissionCollisionChecker;
///
/// fn update_permissions(new_permissions: Vec<String>) -> anyhow::Result<()> {
///     let mut checker = PermissionCollisionChecker::new(new_permissions);
///     let report = checker.validate()?;
///
///     if !report.is_valid() {
///         // Can analyze specific issues
///         for collision in &report.collisions {
///             println!("Hash ID {} has conflicts: {:?}", collision.id, collision.permissions);
///         }
///         return Err(anyhow::anyhow!("Permission validation failed"));
///     }
///
///     // Validation passed - can still inspect the checker
///     let summary = checker.get_permission_summary();
///     println!("Permission distribution: {:?}", summary);
///     Ok(())
/// }
/// ```
pub struct PermissionCollisionChecker {
    permissions: Vec<String>,
    collision_map: HashMap<u32, Vec<String>>,
}

impl PermissionCollisionChecker {
    /// Creates a new collision checker with the given permission strings.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Vector of permission strings to validate
    pub fn new(permissions: Vec<String>) -> Self {
        Self {
            permissions,
            collision_map: HashMap::new(),
        }
    }

    /// Validates all permissions for uniqueness and collision-free hashing.
    ///
    /// This method performs comprehensive validation including:
    /// - Duplicate string detection
    /// - Hash collision detection
    /// - Internal collision map building
    ///
    /// # Returns
    ///
    /// * `Ok(ValidationReport)` - Detailed report of validation results
    /// * `Err(anyhow::Error)` - If validation process itself fails
    ///
    /// # Examples
    ///
    /// ```
    /// use axum_gate::PermissionCollisionChecker;
    ///
    /// let permissions = vec!["read:file".to_string(), "write:file".to_string()];
    /// let mut checker = PermissionCollisionChecker::new(permissions);
    ///
    /// match checker.validate() {
    ///     Ok(report) => {
    ///         if report.is_valid() {
    ///             println!("Validation passed!");
    ///         } else {
    ///             eprintln!("Validation failed: {}", report.summary());
    ///         }
    ///     }
    ///     Err(e) => eprintln!("Validation error: {}", e),
    /// }
    /// ```
    pub fn validate(&mut self) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        // Check for hash collisions (including duplicates)
        self.check_hash_collisions(&mut report).map_err(|e| {
            Error::Domain(DomainError::permission_collision(
                0,
                vec![format!("Failed to check for hash collisions: {}", e)],
            ))
        })?;

        // Generate collision map for inspection
        self.build_collision_map();

        Ok(report)
    }

    fn check_hash_collisions(&self, report: &mut ValidationReport) -> Result<()> {
        let mut id_to_permissions: HashMap<u32, Vec<String>> = HashMap::new();

        // Group permissions by their hash ID
        for permission in &self.permissions {
            let id = PermissionId::from_name(permission);
            id_to_permissions
                .entry(id.as_u32())
                .or_insert_with(Vec::new)
                .push(permission.clone());
        }

        // Find all hash IDs with multiple permissions
        for (id, permissions) in id_to_permissions {
            if permissions.len() > 1 {
                report
                    .collisions
                    .push(PermissionCollision { id, permissions });
            }
        }

        Ok(())
    }

    fn build_collision_map(&mut self) {
        self.collision_map.clear();

        for permission in &self.permissions {
            let id = PermissionId::from_name(permission).as_u32();
            self.collision_map
                .entry(id)
                .or_insert_with(Vec::new)
                .push(permission.clone());
        }
    }

    /// Returns permissions that hash to the same ID as the given permission.
    ///
    /// This method is useful for debugging collision issues or understanding
    /// how permissions map to hash IDs.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission string to check for conflicts
    ///
    /// # Returns
    ///
    /// Vector of permission strings that conflict with the given permission.
    /// The returned vector will not include the input permission itself.
    pub fn get_conflicting_permissions(&self, permission: &str) -> Vec<String> {
        let id = PermissionId::from_name(permission).as_u32();
        self.collision_map
            .get(&id)
            .map(|perms| perms.iter().filter(|p| *p != permission).cloned().collect())
            .unwrap_or_default()
    }

    /// Returns a summary of all permissions grouped by their hash ID.
    ///
    /// This method provides a complete view of how permissions are distributed
    /// across hash IDs, which can be useful for analysis and debugging.
    ///
    /// # Returns
    ///
    /// HashMap where keys are hash IDs and values are vectors of permission strings
    /// that hash to that ID.
    pub fn get_permission_summary(&self) -> HashMap<u32, Vec<String>> {
        self.collision_map.clone()
    }

    /// Returns the total number of permissions being validated.
    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    /// Returns the number of unique hash IDs generated from the permissions.
    pub fn unique_id_count(&self) -> usize {
        self.collision_map.len()
    }
}

/// Detailed report of permission validation results.
///
/// This struct contains comprehensive information about validation results,
/// including any duplicates found and hash collisions detected.
#[derive(Debug, Default)]
pub struct ValidationReport {
    /// List of hash collisions detected.
    pub collisions: Vec<PermissionCollision>,
}

/// Information about a detected hash collision.
///
/// Contains the colliding hash ID and all permission strings that hash to that ID.
#[derive(Debug, Clone)]
pub struct PermissionCollision {
    /// The hash ID that has multiple permissions mapping to it.
    pub id: u32,
    /// List of permission strings that all hash to the same ID.
    pub permissions: Vec<String>,
}

impl ValidationReport {
    /// Returns true if validation passed without any issues.
    ///
    /// A validation is considered successful if there are no hash collisions.
    pub fn is_valid(&self) -> bool {
        self.collisions.is_empty()
    }

    /// Returns duplicate permission strings found.
    ///
    /// Duplicates are derived from collisions where all permissions are identical.
    pub fn duplicates(&self) -> Vec<String> {
        self.collisions
            .iter()
            .filter(|collision| {
                collision.permissions.len() > 1
                    && collision.permissions.windows(2).all(|w| w[0] == w[1])
            })
            .map(|collision| collision.permissions[0].clone())
            .collect()
    }

    /// Returns a human-readable summary of validation results.
    ///
    /// For successful validations, returns a success message.
    /// For failed validations, provides details about what issues were found.
    pub fn summary(&self) -> String {
        if self.is_valid() {
            return "All permissions are valid and collision-free".to_string();
        }

        let mut parts = Vec::new();
        let duplicates = self.duplicates();

        if !duplicates.is_empty() {
            parts.push(format!(
                "{} duplicate permission string(s)",
                duplicates.len()
            ));
        }

        let non_duplicate_collisions = self
            .collisions
            .iter()
            .filter(|collision| {
                !(collision.permissions.len() > 1
                    && collision.permissions.windows(2).all(|w| w[0] == w[1]))
            })
            .count();

        if non_duplicate_collisions > 0 {
            let total_colliding = self
                .collisions
                .iter()
                .filter(|collision| {
                    !(collision.permissions.len() > 1
                        && collision.permissions.windows(2).all(|w| w[0] == w[1]))
                })
                .map(|c| c.permissions.len())
                .sum::<usize>();
            parts.push(format!(
                "{} hash collision(s) affecting {} permission(s)",
                non_duplicate_collisions, total_colliding
            ));
        }

        parts.join(", ")
    }

    /// Logs validation results using the tracing crate.
    ///
    /// This method will log at INFO level for successful validations
    /// and WARN level for any issues found.
    pub fn log_results(&self) {
        if self.is_valid() {
            info!("Permission validation passed: all permissions are valid");
            return;
        }

        let duplicates = self.duplicates();
        for duplicate in &duplicates {
            warn!("Duplicate permission string found: '{}'", duplicate);
        }

        for collision in &self.collisions {
            let is_duplicate = collision.permissions.len() > 1
                && collision.permissions.windows(2).all(|w| w[0] == w[1]);
            if !is_duplicate {
                warn!(
                    "Hash collision detected (ID: {}): permissions {:?} all hash to the same value",
                    collision.id, collision.permissions
                );
            }
        }
    }

    /// Returns detailed information about all issues found.
    ///
    /// This method provides comprehensive details suitable for debugging
    /// or detailed error reporting.
    pub fn detailed_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let duplicates = self.duplicates();

        for duplicate in &duplicates {
            errors.push(format!("Duplicate permission: '{}'", duplicate));
        }

        for collision in &self.collisions {
            let is_duplicate = collision.permissions.len() > 1
                && collision.permissions.windows(2).all(|w| w[0] == w[1]);
            if !is_duplicate {
                errors.push(format!(
                    "Hash collision (ID {}): {} -> {:?}",
                    collision.id,
                    collision.permissions.join(", "),
                    collision.permissions
                ));
            }
        }

        errors
    }

    /// Returns the total number of issues found.
    pub fn total_issues(&self) -> usize {
        self.collisions.len()
    }
}

/// High-level builder pattern validator for application startup validation.
///
/// This is a high-level interface for validating permissions from multiple sources
/// during application initialization. It provides an ergonomic API for collecting
/// permissions incrementally before validation.
///
/// ## Use Cases
///
/// - **Application startup**: Validate permissions loaded from config, database, etc.
/// - **Simple validation workflows**: Need basic validation with automatic logging
/// - **Builder pattern preference**: Want to incrementally add permissions from different sources
/// - **One-time validation**: Don't need post-validation analysis
///
/// ## Compared to PermissionCollisionChecker
///
/// - **State**: Stateless builder - consumed during validation
/// - **Usage**: Builder pattern with incremental permission addition
/// - **Methods**: Focus on building and validating, no post-validation introspection
/// - **Lifecycle**: Single-use - transforms into validation report
/// - **Logging**: Automatically logs validation results
///
/// For runtime validation or when you need to analyze collision details after validation,
/// use [`PermissionCollisionChecker`] directly.
///
/// # See Also
///
/// - [`PermissionCollisionChecker`] - Low-level validator with detailed analysis capabilities
///
/// # Examples
///
/// ## Application startup validation
///
/// ```
/// use axum_gate::ApplicationValidator;
///
/// # fn load_config_permissions() -> Vec<String> { vec!["user:read".to_string()] }
/// # async fn load_db_permissions() -> anyhow::Result<Vec<String>> { Ok(vec!["admin:write".to_string()]) }
/// # async fn example() -> anyhow::Result<()> {
/// // Collect permissions from multiple sources during startup
/// let config_permissions = load_config_permissions();
/// let db_permissions = load_db_permissions().await?;
///
/// let report = ApplicationValidator::new()
///     .add_permissions(config_permissions)
///     .add_permissions(db_permissions)
///     .add_permission("system:health")  // Add individual permissions
///     .validate()?;  // Automatically logs results
///
/// if report.is_valid() {
///     println!("✓ All permissions validated - server can start");
/// } else {
///     return Err(anyhow::anyhow!("Permission validation failed: {}", report.summary()));
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Simple validation workflow
///
/// ```
/// use axum_gate::ApplicationValidator;
///
/// // For simple cases where you just need pass/fail validation
/// let report = ApplicationValidator::new()
///     .add_permissions(["user:read", "user:write", "admin:delete"])
///     .validate()?;
///
/// // Report is automatically logged, just check if valid
/// if !report.is_valid() {
///     panic!("Invalid permissions detected during startup");
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
///
/// ## Comparison with PermissionCollisionChecker
///
/// ```
/// use axum_gate::{ApplicationValidator, PermissionCollisionChecker};
///
/// let permissions = vec!["user:read".to_string(), "user:write".to_string()];
///
/// // ApplicationValidator: Builder pattern, single-use, automatic logging
/// let report1 = ApplicationValidator::new()
///     .add_permissions(permissions.clone())
///     .validate()?;  // Validator is consumed here
/// // Can't use validator anymore, but don't need to
///
/// // PermissionCollisionChecker: Direct instantiation, reusable, manual control
/// let mut checker = PermissionCollisionChecker::new(permissions);
/// let report2 = checker.validate()?;  // Checker is still available
///
/// // Can continue using checker for analysis
/// if !report2.is_valid() {
///     let conflicts = checker.get_conflicting_permissions("user:read");
///     println!("Conflicts found: {:?}", conflicts);
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct ApplicationValidator {
    permissions: Vec<String>,
}

impl ApplicationValidator {
    /// Creates a new application validator.
    pub fn new() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    /// Add permissions from an iterator of string-like types.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Iterator of items that can be converted to String
    pub fn add_permissions<I, S>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.permissions
            .extend(permissions.into_iter().map(|s| s.into()));
        self
    }

    /// Add permissions from a vector of strings.
    ///
    /// This is a convenience method for adding permissions that are already
    /// in String format.
    ///
    /// # Arguments
    ///
    /// * `permissions` - Vector of permission strings
    pub fn add_permission_strings(mut self, permissions: Vec<String>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add a single permission string.
    ///
    /// # Arguments
    ///
    /// * `permission` - A single permission string to add
    pub fn add_permission<S: Into<String>>(mut self, permission: S) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Validate all permissions and return detailed report.
    ///
    /// This method performs validation and logs results automatically.
    /// It returns a ValidationReport containing all validation details,
    /// regardless of whether validation passed or failed.
    ///
    /// # Returns
    ///
    /// * `Ok(ValidationReport)` - Complete validation report
    /// * `Err(anyhow::Error)` - Validation process failed
    pub fn validate(self) -> Result<ValidationReport> {
        let mut checker = PermissionCollisionChecker::new(self.permissions);
        let report = checker.validate().map_err(|e| {
            Error::Domain(DomainError::permission_collision(
                0,
                vec![format!("Permission validation process failed: {}", e)],
            ))
        })?;

        report.log_results();

        if report.is_valid() {
            info!("✓ Permission validation completed successfully");
        }

        Ok(report)
    }

    /// Returns the current number of permissions to be validated.
    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }
}

impl Default for ApplicationValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collision_checker_valid_permissions() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "admin:delete".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker.validate().unwrap();

        assert!(report.is_valid());
        assert!(report.duplicates().is_empty());
        assert!(report.collisions.is_empty());
    }

    #[test]
    fn collision_checker_duplicate_strings() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "user:read".to_string(), // Duplicate
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        let report = checker.validate().unwrap();

        assert!(!report.is_valid());
        let duplicates = report.duplicates();
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0], "user:read");
        assert_eq!(report.collisions.len(), 1);
    }

    #[test]
    fn collision_checker_conflicting_permissions() {
        let permissions = vec!["user:read".to_string(), "user:write".to_string()];

        let mut checker = PermissionCollisionChecker::new(permissions);
        checker.validate().unwrap();

        let conflicts = checker.get_conflicting_permissions("user:read");
        // Since these shouldn't hash to the same value, conflicts should be empty
        assert!(conflicts.is_empty());
    }

    #[test]
    fn validation_report_summary() {
        let mut report = ValidationReport::default();
        assert!(report.is_valid());
        assert!(report.summary().contains("valid"));

        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["test".to_string(), "test".to_string()],
        });
        assert!(!report.is_valid());
        assert!(report.summary().contains("duplicate"));

        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["perm1".to_string(), "perm2".to_string()],
        });
        assert!(report.summary().contains("collision"));
    }

    #[test]
    fn application_validator_basic() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:write"])
            .add_permission("admin:delete")
            .validate();

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.is_valid());
    }

    #[test]
    fn application_validator_with_duplicates() {
        let result = ApplicationValidator::new()
            .add_permissions(["user:read", "user:read"])
            .validate();

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.is_valid());
        assert!(!report.duplicates().is_empty());
    }

    #[test]
    fn validation_report_detailed_errors() {
        let mut report = ValidationReport::default();
        report.collisions.push(PermissionCollision {
            id: 54321,
            permissions: vec!["test:duplicate".to_string(), "test:duplicate".to_string()],
        });
        report.collisions.push(PermissionCollision {
            id: 12345,
            permissions: vec!["perm1".to_string(), "perm2".to_string()],
        });

        let errors = report.detailed_errors();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("Duplicate"));
        assert!(errors[1].contains("Hash collision"));
    }

    #[test]
    fn permission_collision_checker_summary() {
        let permissions = vec![
            "user:read".to_string(),
            "user:write".to_string(),
            "admin:delete".to_string(),
        ];

        let mut checker = PermissionCollisionChecker::new(permissions);
        checker.validate().unwrap();

        assert_eq!(checker.permission_count(), 3);
        // Should have 3 unique IDs (assuming no collisions)
        assert_eq!(checker.unique_id_count(), 3);

        let summary = checker.get_permission_summary();
        assert_eq!(summary.len(), 3);
    }
}
