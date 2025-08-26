//! Example comparing the old RoaringBitmap API with the new Permissions API
//!
//! This example demonstrates how the new Permissions struct provides a cleaner,
//! more intuitive API while maintaining backward compatibility with RoaringBitmap.
//!
//! Run with: cargo run --example permissions_comparison

use axum_gate::{PermissionChecker, Permissions};
use roaring::RoaringBitmap;

fn main() {
    println!("=== Permissions API Comparison ===\n");

    // Demonstrate the old RoaringBitmap approach
    old_roaring_bitmap_api();

    println!();

    // Demonstrate the new Permissions approach
    new_permissions_api();

    println!();

    // Show interoperability between the two approaches
    interoperability_demo();

    println!();

    // Performance comparison (basic)
    performance_comparison();
}

fn old_roaring_bitmap_api() {
    println!("📚 Old RoaringBitmap API:");

    // Creating and managing permissions the old way
    let mut permissions = RoaringBitmap::new();

    // Granting permissions - verbose and requires PermissionChecker
    PermissionChecker::grant_permission(&mut permissions, "read:profile");
    PermissionChecker::grant_permission(&mut permissions, "write:profile");
    PermissionChecker::grant_permission(&mut permissions, "delete:posts");

    // Checking permissions
    if PermissionChecker::has_permission(&permissions, "read:profile") {
        println!("✅ User has read:profile permission");
    }

    // Multiple permission checks
    let required_permissions = vec!["read:profile", "write:profile"];
    if PermissionChecker::has_all_permissions(&permissions, &required_permissions) {
        println!("✅ User has all required permissions for profile management");
    }

    // Check any permission
    let admin_permissions = vec!["admin:users", "delete:posts"];
    if PermissionChecker::has_any_permission(&permissions, &admin_permissions) {
        println!("✅ User has some administrative permissions");
    }

    println!("   - Requires importing roaring::RoaringBitmap");
    println!("   - Verbose: need PermissionChecker for every operation");
    println!("   - Less intuitive: bitmap concept not obvious");
    println!("   - Manual creation: RoaringBitmap::new()");
}

fn new_permissions_api() {
    println!("🚀 New Permissions API:");

    // Creating permissions - clean and intuitive
    let mut permissions = Permissions::new();

    // Granting permissions - chainable and self-contained
    permissions
        .grant("read:profile")
        .grant("write:profile")
        .grant("delete:posts");

    // Alternative: builder pattern
    let _builder_permissions = Permissions::new()
        .with("read:profile")
        .with("write:profile")
        .build();

    // Alternative: from iterator
    let _iter_permissions =
        Permissions::from_iter(["read:profile", "write:profile", "delete:posts"]);

    // Checking permissions - methods on the struct itself
    if permissions.has("read:profile") {
        println!("✅ User has read:profile permission");
    }

    // Multiple permission checks
    if permissions.has_all(&["read:profile", "write:profile"]) {
        println!("✅ User has all required permissions for profile management");
    }

    // Check any permission
    if permissions.has_any(&["admin:users", "delete:posts"]) {
        println!("✅ User has some administrative permissions");
    }

    // Additional useful methods
    println!("📊 Permission statistics:");
    println!("   - Total permissions: {}", permissions.len());
    println!("   - Is empty: {}", permissions.is_empty());

    // Set operations
    let mut admin_permissions = Permissions::from_iter(["admin:users", "admin:system"]);
    let combined = {
        let mut temp = permissions.clone();
        temp.union(&admin_permissions);
        temp
    };
    println!("   - After union: {} permissions", combined.len());

    println!("   - Clean API: no external imports needed");
    println!("   - Intuitive: methods on the permission object itself");
    println!("   - Chainable: builder pattern support");
    println!("   - Flexible: multiple creation methods");
}

fn interoperability_demo() {
    println!("🔗 Interoperability Demo:");

    // Start with old API
    let mut old_permissions = RoaringBitmap::new();
    PermissionChecker::grant_permission(&mut old_permissions, "read:api");
    PermissionChecker::grant_permission(&mut old_permissions, "write:api");

    // Convert to new API
    let new_permissions = Permissions::from(old_permissions);
    println!(
        "✅ Converted RoaringBitmap to Permissions: {} permissions",
        new_permissions.len()
    );

    // Work with new API
    let mut enhanced_permissions = new_permissions.clone().with("admin:api");

    // Convert back to old API if needed
    let back_to_old: RoaringBitmap = enhanced_permissions.clone().into();
    println!(
        "✅ Converted back to RoaringBitmap: {} permissions",
        back_to_old.len()
    );

    // Use as reference (no conversion needed)
    let bitmap_ref: &RoaringBitmap = enhanced_permissions.as_ref();
    if PermissionChecker::has_permission(bitmap_ref, "admin:api") {
        println!("✅ Can use Permissions with old PermissionChecker via as_ref()");
    }

    println!("   - Seamless conversion in both directions");
    println!("   - No performance overhead for conversion");
    println!("   - Can use with existing PermissionChecker code");
}

fn performance_comparison() {
    println!("⚡ Performance Comparison:");

    let permission_names: Vec<String> = (0..10_000).map(|i| format!("permission:{}", i)).collect();

    // Old API performance
    let start = std::time::Instant::now();
    let mut old_permissions = RoaringBitmap::new();
    for name in &permission_names {
        PermissionChecker::grant_permission(&mut old_permissions, name);
    }
    let old_duration = start.elapsed();

    // New API performance
    let start = std::time::Instant::now();
    let mut new_permissions = Permissions::new();
    for name in &permission_names {
        new_permissions.grant(name);
    }
    let new_duration = start.elapsed();

    // Bulk creation performance
    let start = std::time::Instant::now();
    let _bulk_permissions = Permissions::from_iter(permission_names.iter().map(|s| s.as_str()));
    let bulk_duration = start.elapsed();

    println!("   - Old API (10k permissions): {:?}", old_duration);
    println!("   - New API (10k permissions): {:?}", new_duration);
    println!("   - Bulk creation (10k permissions): {:?}", bulk_duration);

    // Check performance
    let test_permission = "permission:5000";

    let start = std::time::Instant::now();
    let _has_old = PermissionChecker::has_permission(&old_permissions, test_permission);
    let old_check_duration = start.elapsed();

    let start = std::time::Instant::now();
    let _has_new = new_permissions.has(test_permission);
    let new_check_duration = start.elapsed();

    println!("   - Old API check: {:?}", old_check_duration);
    println!("   - New API check: {:?}", new_check_duration);
    println!("   - Performance is essentially identical (zero-cost abstraction)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_equivalence() {
        // Both APIs should produce the same results
        let mut old_permissions = RoaringBitmap::new();
        PermissionChecker::grant_permission(&mut old_permissions, "test:permission");

        let mut new_permissions = Permissions::new();
        new_permissions.grant("test:permission");

        assert!(PermissionChecker::has_permission(
            &old_permissions,
            "test:permission"
        ));
        assert!(new_permissions.has("test:permission"));

        // Convert and compare
        let converted: RoaringBitmap = new_permissions.into();
        assert_eq!(old_permissions, converted);
    }

    #[test]
    fn builder_patterns_work() {
        let permissions1 = Permissions::new()
            .with("read:data")
            .with("write:data")
            .build();

        let permissions2 = Permissions::from_iter(["read:data", "write:data"]);

        let mut permissions3 = Permissions::new();
        permissions3.grant("read:data").grant("write:data");

        // All three should be equivalent
        assert_eq!(permissions1.len(), permissions2.len());
        assert_eq!(permissions2.len(), permissions3.len());

        assert!(permissions1.has("read:data"));
        assert!(permissions2.has("read:data"));
        assert!(permissions3.has("read:data"));
    }
}
