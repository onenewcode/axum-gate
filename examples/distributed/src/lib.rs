//! Distributed system example demonstrating zero-synchronization permissions.
//!
//! This example shows how the new permission system works seamlessly across
//! distributed nodes without any coordination or synchronization.

use axum_gate::{PermissionChecker, PermissionId, validate_permissions};
use roaring::RoaringBitmap;

/// Application permissions using the new zero-sync system.
///
/// These permissions work identically across all nodes without any coordination.
/// Each permission name deterministically maps to the same ID on every node.
pub struct AppPermissions;

impl AppPermissions {
    // Define permission constants for type safety and documentation
    pub const READ_REPOSITORY: &'static str = "read:repository";
    pub const WRITE_REPOSITORY: &'static str = "write:repository";
    pub const READ_API: &'static str = "read:api";
    pub const WRITE_API: &'static str = "write:api";
    pub const DELETE_REPOSITORY: &'static str = "delete:repository";
    pub const ADMIN_SYSTEM: &'static str = "admin:system";
}

// Validate permissions at compile time to ensure no hash collisions
validate_permissions![
    "read:repository",
    "write:repository",
    "read:api",
    "write:api",
    "delete:repository",
    "admin:system"
];

/// Helper functions for common permission operations.
pub struct PermissionHelper;

impl PermissionHelper {
    /// Grant repository access (read + write).
    pub fn grant_repository_access(user_permissions: &mut RoaringBitmap) {
        PermissionChecker::grant_permission(user_permissions, AppPermissions::READ_REPOSITORY);
        PermissionChecker::grant_permission(user_permissions, AppPermissions::WRITE_REPOSITORY);
    }

    /// Grant API access (read + write).
    pub fn grant_api_access(user_permissions: &mut RoaringBitmap) {
        PermissionChecker::grant_permission(user_permissions, AppPermissions::READ_API);
        PermissionChecker::grant_permission(user_permissions, AppPermissions::WRITE_API);
    }

    /// Grant admin access (all permissions).
    pub fn grant_admin_access(user_permissions: &mut RoaringBitmap) {
        Self::grant_repository_access(user_permissions);
        Self::grant_api_access(user_permissions);
        PermissionChecker::grant_permission(user_permissions, AppPermissions::DELETE_REPOSITORY);
        PermissionChecker::grant_permission(user_permissions, AppPermissions::ADMIN_SYSTEM);
    }

    /// Check if user can access repository data.
    pub fn can_access_repository(user_permissions: &RoaringBitmap) -> bool {
        PermissionChecker::has_permission(user_permissions, AppPermissions::READ_REPOSITORY)
    }

    /// Check if user can modify repository data.
    pub fn can_modify_repository(user_permissions: &RoaringBitmap) -> bool {
        PermissionChecker::has_permission(user_permissions, AppPermissions::WRITE_REPOSITORY)
    }

    /// Check if user can access API.
    pub fn can_access_api(user_permissions: &RoaringBitmap) -> bool {
        PermissionChecker::has_permission(user_permissions, AppPermissions::READ_API)
    }

    /// Check if user is admin.
    pub fn is_admin(user_permissions: &RoaringBitmap) -> bool {
        PermissionChecker::has_permission(user_permissions, AppPermissions::ADMIN_SYSTEM)
    }
}

/// Demonstrates zero-sync permission operations.
pub fn demonstrate_zero_sync() {
    println!("=== Zero-Sync Permission System Demo ===\n");

    // Show deterministic permission ID generation
    println!("1. Deterministic Permission IDs:");
    let read_repo_id = PermissionId::from_name(AppPermissions::READ_REPOSITORY);
    let write_repo_id = PermissionId::from_name(AppPermissions::WRITE_REPOSITORY);

    println!(
        "  '{}' -> ID: {}",
        AppPermissions::READ_REPOSITORY,
        read_repo_id
    );
    println!(
        "  '{}' -> ID: {}",
        AppPermissions::WRITE_REPOSITORY,
        write_repo_id
    );

    // Demonstrate that IDs are always the same
    let read_repo_id_again = PermissionId::from_name(AppPermissions::READ_REPOSITORY);
    println!(
        "  Same permission generates same ID: {} == {} = {}",
        read_repo_id,
        read_repo_id_again,
        read_repo_id == read_repo_id_again
    );
    println!();

    // Create user permissions
    println!("2. User Permission Management:");
    let mut user_permissions = RoaringBitmap::new();

    // Grant some permissions
    PermissionHelper::grant_repository_access(&mut user_permissions);
    PermissionChecker::grant_permission(&mut user_permissions, AppPermissions::READ_API);

    println!("  Granted: repository access + read API");
    println!(
        "  Can access repository: {}",
        PermissionHelper::can_access_repository(&user_permissions)
    );
    println!(
        "  Can modify repository: {}",
        PermissionHelper::can_modify_repository(&user_permissions)
    );
    println!(
        "  Can access API: {}",
        PermissionHelper::can_access_api(&user_permissions)
    );
    println!(
        "  Is admin: {}",
        PermissionHelper::is_admin(&user_permissions)
    );
    println!();

    // Show distributed scenario
    println!("3. Distributed System Scenario:");
    println!("  Auth Node: Issues JWT with permission bitmap");
    println!("  Data Node: Validates permissions without any communication");
    println!();

    // Simulate auth node creating JWT payload
    let jwt_permission_bitmap = user_permissions.clone();
    println!(
        "  Auth Node: User has permissions bitmap: {:?}",
        jwt_permission_bitmap.iter().collect::<Vec<_>>()
    );

    // Simulate data node checking permissions
    let required_permission = AppPermissions::READ_REPOSITORY;
    let has_access = PermissionChecker::has_permission(&jwt_permission_bitmap, required_permission);
    println!(
        "  Data Node: Checking '{}' -> Access: {}",
        required_permission, has_access
    );

    let admin_permission = AppPermissions::ADMIN_SYSTEM;
    let is_admin = PermissionChecker::has_permission(&jwt_permission_bitmap, admin_permission);
    println!(
        "  Data Node: Checking '{}' -> Access: {}",
        admin_permission, is_admin
    );
    println!();

    println!("4. Key Benefits:");
    println!("  ✓ Zero coordination between nodes");
    println!("  ✓ Deterministic permission IDs");
    println!("  ✓ No synchronization required");
    println!("  ✓ Works instantly across all nodes");
    println!("  ✓ Collision-resistant (SHA-256 based)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_ids_are_deterministic() {
        let id1 = PermissionId::from_name("test:permission");
        let id2 = PermissionId::from_name("test:permission");
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_permissions_have_different_ids() {
        let id1 = PermissionId::from_name("read:file");
        let id2 = PermissionId::from_name("write:file");
        assert_ne!(id1, id2);
    }

    #[test]
    fn permission_validation_works() {
        // This would panic at compile time if there were collisions
        validate_permissions![
            "test:permission:1",
            "test:permission:2",
            "test:permission:3"
        ];
    }

    #[test]
    fn helper_functions_work() {
        let mut permissions = RoaringBitmap::new();

        assert!(!PermissionHelper::can_access_repository(&permissions));

        PermissionHelper::grant_repository_access(&mut permissions);
        assert!(PermissionHelper::can_access_repository(&permissions));
        assert!(PermissionHelper::can_modify_repository(&permissions));

        assert!(!PermissionHelper::is_admin(&permissions));
        PermissionHelper::grant_admin_access(&mut permissions);
        assert!(PermissionHelper::is_admin(&permissions));
    }
}

/// Main function to run the demonstration.
///
/// Run with: `cargo run --bin demo` from the distributed example directory.
pub fn main() {
    demonstrate_zero_sync();

    println!("\n=== Performance Comparison ===");

    // Show the performance advantage
    let start = std::time::Instant::now();
    for _ in 0..100_000 {
        let _id = PermissionId::from_name("read:repository");
    }
    let duration = start.elapsed();
    println!(
        "Generated 100,000 permission IDs in: {:?} ({:.2} ns per ID)",
        duration,
        duration.as_nanos() as f64 / 100_000.0
    );

    // Show bitmap operations
    let mut permissions = RoaringBitmap::new();
    let start = std::time::Instant::now();
    for i in 0..100_000 {
        let perm_name = format!("permission:{}", i);
        PermissionChecker::grant_permission(&mut permissions, &perm_name);
    }
    let grant_duration = start.elapsed();

    let start = std::time::Instant::now();
    for i in 0..100_000 {
        let perm_name = format!("permission:{}", i);
        let _has = PermissionChecker::has_permission(&permissions, &perm_name);
    }
    let check_duration = start.elapsed();

    println!(
        "Granted 100,000 permissions in: {:?} ({:.2} ns per grant)",
        grant_duration,
        grant_duration.as_nanos() as f64 / 100_000.0
    );
    println!(
        "Checked 100,000 permissions in: {:?} ({:.2} ns per check)",
        check_duration,
        check_duration.as_nanos() as f64 / 100_000.0
    );

    println!("\n=== Zero-Sync vs Traditional Sync ===");
    println!("Traditional (old) approach:");
    println!("  - Requires permission set synchronization");
    println!("  - Network calls to coordinate changes");
    println!("  - Complex deployment coordination");
    println!("  - Risk of permission corruption");
    println!();
    println!("Zero-Sync (new) approach:");
    println!("  ✓ No synchronization required");
    println!("  ✓ Zero network overhead");
    println!("  ✓ Instant deployment");
    println!("  ✓ Collision-resistant");
    println!("  ✓ High performance");
}
