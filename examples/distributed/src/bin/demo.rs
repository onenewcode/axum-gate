//! Demo binary showing the zero-synchronization permission system.
//!
//! This demonstrates how the new permission system works without any
//! coordination between distributed nodes.
//!
//! Run with: `cargo run --bin demo`

fn main() {
    println!("🚀 Axum-Gate Zero-Sync Permission System Demo\n");

    // Run the demonstration
    distributed::main();

    println!("\n=== How to Use in Your Application ===");
    println!();
    println!("1. Define your permissions:");
    println!("   ```rust");
    println!("   use axum_gate::{{PermissionChecker, validate_permissions}};");
    println!("   ");
    println!("   // Validate at compile time");
    println!("   validate_permissions![");
    println!("       \"user:read\",");
    println!("       \"user:write\",");
    println!("       \"system:admin\"");
    println!("   ];");
    println!("   ```");
    println!();
    println!("2. Define nested enum permissions:");
    println!("   ```rust");
    println!("   #[derive(Display, EnumString, Serialize, Deserialize)]");
    println!("   pub enum AppPermissions {{");
    println!("       User(UserPermission),");
    println!("       System(SystemPermission),");
    println!("   }}");
    println!("   ```");
    println!();
    println!("3. Grant permissions to users:");
    println!("   ```rust");
    println!(
        "   PermissionHelper::grant_permission(&mut user.permissions, &AppPermissions::Repository(RepositoryPermission::Read));"
    );
    println!("   ```");
    println!();
    println!("4. Check permissions in route handlers:");
    println!("   ```rust");
    println!(
        "   if PermissionHelper::has_permission(&user.permissions, &AppPermissions::Repository(RepositoryPermission::Read)) {{"
    );
    println!("       // Grant access");
    println!("   }}");
    println!("   ```");
    println!();
    println!("5. Use with Gates:");
    println!("   ```rust");
    println!("   .layer(");
    println!("       Gate::new_cookie(issuer, codec)");
    println!(
        "           .grant_permission(PermissionId::from(AppPermissions::Repository(RepositoryPermission::Read).as_str()))"
    );
    println!("   )");
    println!("   ```");
    println!();
    println!(
        "✨ That's it! Type-safe, serializable, no synchronization, no coordination, just works!"
    );
}
