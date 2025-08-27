//! Simple usage example showcasing the improved API design.
//!
//! This example demonstrates how the restructured API makes common
//! authentication tasks much more straightforward and fun to use.

use axum_gate::{
    storage::{MemoryAccountRepository, MemorySecretRepository},
    AccessPolicy, Account, AccountInsertService, Gate, Group, JsonWebToken,
    JwtClaims, Role, login, logout, Credentials, RegisteredClaims, CookieJar
};

use std::sync::Arc;

use serde::Deserialize;
use axum::{extract::Extension, routing::get, Router, Json};

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::init();

    // Set up storage (in-memory for this example)
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repo = Arc::new(MemorySecretRepository::default());

    // Create some test users
    create_test_users(Arc::clone(&account_repo), Arc::clone(&secret_repo)).await;

    // Create JWT codec
    let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

    // Build app with different protection levels
    let app = Router::new()
        // Admin-only area - super simple!
        .route("/admin", get(admin_handler))
        .layer(
            Gate::cookie_deny_all("my-app", Arc::clone(&jwt_codec))
                .with_policy(AccessPolicy::require_role(Role::Admin))
        )

        // Staff area - multiple roles allowed
        .route("/staff", get(staff_handler))
        .layer(
            Gate::cookie_deny_all("my-app", Arc::clone(&jwt_codec))
                .with_policy(
                    AccessPolicy::require_role(Role::Admin)
                        .or_require_role(Role::Moderator)
                )
        )

        // Engineering team area - group-based access
        .route("/engineering", get(engineering_handler))
        .layer(
            Gate::cookie_deny_all("my-app", Arc::clone(&jwt_codec))
                .with_policy(AccessPolicy::require_group(Group::new("engineering")))
        )

        // Any logged-in user
        .route("/profile", get(profile_handler))
        .layer(
            Gate::cookie_deny_all("my-app", Arc::clone(&jwt_codec))
                .with_policy(
                    AccessPolicy::require_role(Role::User)
                        .or_require_role(Role::Reporter)
                        .or_require_role(Role::Moderator)
                        .or_require_role(Role::Admin)
                )
        )

        // Authentication endpoints - clean and simple
        .route("/login", axum::routing::post(login_handler))
        .route("/logout", axum::routing::post(logout_handler))

        // Public endpoint - no protection
        .route("/", get(|| async { "🌍 Welcome! Try logging in with admin/admin" }))

        // Add repositories and JWT codec to state for handlers
        .with_state(AppState {
            account_repo,
            secret_repo,
            jwt_codec,
        });

    println!("🚀 Server starting on http://localhost:3000");
    println!("📚 Available endpoints:");
    println!("  • GET  / - Public welcome message");
    println!("  • POST /login - Login (try admin/admin or user/user)");
    println!("  • POST /logout - Logout");
    println!("  • GET  /profile - Any logged-in user");
    println!("  • GET  /staff - Admin or Moderator only");
    println!("  • GET  /engineering - Engineering group only");
    println!("  • GET  /admin - Admin role only");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

#[derive(Clone)]
struct AppState {
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
    jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>>,
}

// Route handlers - notice how clean they are!

async fn admin_handler(Extension(user): Extension<Account<Role, Group>>) -> String {
    format!("🔐 Admin Area\nWelcome {}!\nYour roles: {:?}", user.user_id, user.roles)
}

async fn staff_handler(Extension(user): Extension<Account<Role, Group>>) -> String {
    format!("👥 Staff Area\nWelcome {}!\nYour roles: {:?}", user.user_id, user.roles)
}

async fn engineering_handler(Extension(user): Extension<Account<Role, Group>>) -> String {
    format!("⚙️  Engineering Area\nWelcome {}!\nYour groups: {:?}", user.user_id, user.groups)
}

async fn profile_handler(Extension(user): Extension<Account<Role, Group>>) -> String {
    format!(
        "👤 Your Profile\n\nUser ID: {}\nRoles: {:?}\nGroups: {:?}\nPermissions: {} total",
        user.user_id, user.roles, user.groups, user.permissions.count()
    )
}

// Authentication handlers using the existing login/logout functions

async fn login_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    cookie_jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<CookieJar, axum::http::StatusCode> {
    let credentials = Credentials::new(request.username, request.password);
    let registered_claims = RegisteredClaims::new(
        "my-app",
        (chrono::Utc::now().timestamp() + 3600) as u64, // 1 hour expiry
    );

    let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-token", "")
        .http_only(true)
        .secure(false) // Set to true in production with HTTPS
        .max_age(axum_gate::Duration::hours(24));

    login(
        cookie_jar,
        Json(credentials),
        registered_claims,
        state.secret_repo,
        state.account_repo,
        state.jwt_codec,
        cookie_template,
    ).await
}

async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
    let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-token", "");
    logout(cookie_jar, cookie_template).await
}

// Helper function to create test data

async fn create_test_users(
    account_repo: Arc<MemoryAccountRepository<Role, Group>>,
    secret_repo: Arc<MemorySecretRepository>,
) {
    // Admin user
    let _ = AccountInsertService::insert("admin", "admin")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("leadership")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Moderator user
    let _ = AccountInsertService::insert("moderator", "moderator")
        .with_roles(vec![Role::Moderator])
        .with_groups(vec![Group::new("staff")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Engineering user
    let _ = AccountInsertService::insert("engineer", "engineer")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("engineering")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    // Regular user
    let _ = AccountInsertService::insert("user", "user")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("customers")])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await;

    println!("✅ Test users created:");
    println!("   • admin/admin (Admin role, leadership group)");
    println!("   • moderator/moderator (Moderator role, staff group)");
    println!("   • engineer/engineer (User role, engineering group)");
    println!("   • user/user (User role, customers group)");
}
