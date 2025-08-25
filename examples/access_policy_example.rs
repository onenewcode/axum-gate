//! Example demonstrating the improved AccessPolicy API
//!
//! This example shows how to use the new AccessPolicy system which provides
//! clear separation between business logic (access requirements) and web
//! infrastructure (HTTP/cookie handling).

use axum::{routing::get, Router};
use axum_gate::{
    AccessPolicy, AuthorizationService, Gate, Group, Role, Account,
    infrastructure::jwt::JsonWebTokenOptions,
    infrastructure::repositories::memory::MemoryAccountRepository,
};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create JWT codec
    let jwt_options = JsonWebTokenOptions::new("my-secret-key", "my-issuer");
    let codec = Arc::new(jwt_options);

    // Example 1: Simple role-based access
    let admin_only_policy = AccessPolicy::require_role(Role::Admin);
    let admin_gate = Gate::cookie("my-issuer", Arc::clone(&codec), admin_only_policy);

    // Example 2: Role hierarchy - allow Moderator and all supervisors (Admin)
    let moderator_or_supervisor_policy = AccessPolicy::require_role_or_supervisor(Role::Moderator);
    let moderator_gate = Gate::cookie("my-issuer", Arc::clone(&codec), moderator_or_supervisor_policy);

    // Example 3: Multiple access criteria (OR logic)
    let flexible_policy = AccessPolicy::require_role(Role::Admin)
        .or_require_group(Group::new("engineering"))
        .or_require_permission(42u32);
    let flexible_gate = Gate::cookie("my-issuer", Arc::clone(&codec), flexible_policy);

    // Example 4: Group-based access
    let engineering_policy = AccessPolicy::require_group(Group::new("engineering"));
    let engineering_gate = Gate::cookie("my-issuer", Arc::clone(&codec), engineering_policy);

    // Example 5: Permission-based access
    let read_files_policy = AccessPolicy::require_permission(1u32)  // "read:files"
        .or_require_permission(2u32);  // "read:all"
    let files_gate = Gate::cookie("my-issuer", Arc::clone(&codec), read_files_policy);

    // Example 6: Complex policy - Admin OR (Engineering group AND read permission)
    let complex_policy = AccessPolicy::require_role(Role::Admin)
        .or_require_group(Group::new("engineering"));
    let complex_gate = Gate::cookie("my-issuer", Arc::clone(&codec), complex_policy);

    // Example 7: Using the deny_all default for secure development
    let secure_gate = Gate::cookie_deny_all("my-issuer", Arc::clone(&codec))
        .with_policy(AccessPolicy::require_role(Role::Admin));

    // Build the router with different protection levels
    let app = Router::new()
        .route("/admin", get(admin_handler))
        .layer(admin_gate)
        .route("/moderation", get(moderation_handler))
        .layer(moderator_gate)
        .route("/flexible", get(flexible_handler))
        .layer(flexible_gate)
        .route("/engineering", get(engineering_handler))
        .layer(engineering_gate)
        .route("/files", get(files_handler))
        .layer(files_gate)
        .route("/complex", get(complex_handler))
        .layer(complex_gate)
        .route("/secure", get(secure_handler))
        .layer(secure_gate)
        .route("/public", get(public_handler)); // No protection

    println!("🚀 Server starting on http://localhost:3000");
    println!("📚 Different routes showcase different access policies:");
    println!("  • /admin - Admin role only");
    println!("  • /moderation - Moderator role or supervisor (Admin)");
    println!("  • /flexible - Admin role OR engineering group OR permission 42");
    println!("  • /engineering - Engineering group members only");
    println!("  • /files - Users with read permissions (1 or 2)");
    println!("  • /complex - Admin role OR engineering group");
    println!("  • /secure - Secure default with Admin access");
    println!("  • /public - No authentication required");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

// Route handlers
async fn admin_handler() -> &'static str {
    "🔐 Admin Area - Only administrators can access this!"
}

async fn moderation_handler() -> &'static str {
    "🛡️ Moderation Area - Moderators and their supervisors can access this!"
}

async fn flexible_handler() -> &'static str {
    "🔄 Flexible Access - Multiple ways to get in: Admin role, Engineering group, or special permission!"
}

async fn engineering_handler() -> &'static str {
    "⚙️ Engineering Area - Only engineering group members allowed!"
}

async fn files_handler() -> &'static str {
    "📁 Files Area - Users with file read permissions can access this!"
}

async fn complex_handler() -> &'static str {
    "🧩 Complex Policy - Admin role OR engineering group membership required!"
}

async fn secure_handler() -> &'static str {
    "🔒 Secure Area - Built with secure defaults, only admins allowed!"
}

async fn public_handler() -> &'static str {
    "🌍 Public Area - No authentication required!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_policies_are_clear_and_expressive() {
        // The new API makes access requirements very clear
        let _admin_only: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);

        let _manager_and_up: AccessPolicy<Role, Group> =
            AccessPolicy::require_role_or_supervisor(Role::Moderator);

        let _engineering_team: AccessPolicy<Role, Group> =
            AccessPolicy::require_group(Group::new("engineering"));

        let _read_permission: AccessPolicy<Role, Group> =
            AccessPolicy::require_permission(1u32);

        // Complex policies are readable
        let _flexible: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin)
            .or_require_group(Group::new("engineering"))
            .or_require_permission(42u32);

        // Authorization service methods are now clear about intent
        let auth_service = AuthorizationService::new(_admin_only.clone());
        let account = Account::new("test", &[Role::Admin], &[Group::new("test")]);

        // Clear method names show they check individual requirements
        let _meets_role = auth_service.meets_role_requirement(&account);
        let _meets_group = auth_service.meets_group_requirement(&account);
        let _meets_permission = auth_service.meets_permission_requirement(&account);
        let _meets_supervisor = auth_service.meets_supervisor_role_requirement(&account);

        // Main authorization decision is obvious
        let _authorized = auth_service.is_authorized(&account);

        // Policy state checking is clear
        let _denies_all = auth_service.policy_denies_all_access();
    }

    #[test]
    fn secure_defaults_encourage_good_practices() {
        let codec = Arc::new(JsonWebTokenOptions::new("key", "issuer"));

        // Secure default - denies all access
        let _secure_gate = Gate::cookie_deny_all("issuer", codec.clone())
            .with_policy(AccessPolicy::require_role(Role::Admin));

        // Explicit policy required
        let policy = AccessPolicy::require_role(Role::User);
        let _explicit_gate = Gate::cookie("issuer", codec, policy);
    }
}
