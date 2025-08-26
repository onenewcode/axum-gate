# axum-gate

Fully customizable role-based JWT cookie authentication for axum, designed for both single nodes and distributed systems.

`axum-gate` provides a high-level API for role-based access control within `axum` applications. It uses composition of different services to enable maximum flexibility for any specific use case, with encryption/encoding handled by external crates.

## Features

- Role-based access authentication for `axum` using JWT cookies
- Support for custom roles and groups
- Works with single nodes and distributed systems
- Separate storage of `Account` and `Secret` information for enhanced security
- Built-in support for `surrealdb`, `sea-orm`, and in-memory storages
- Pre-defined handlers for easy integration
- Static and dynamic permission systems for fine-grained access control
- Compile-time and runtime permission validation with collision detection

## Planned Features

- Bearer token authentication layer with rotating key sets
- Additional storage backend implementations

## Quick Start

To protect your application with `axum-gate`, you need storage implementations for accounts and secrets. Here's a complete example using the in-memory storage:

```rust
use axum::{routing::get, Router};
use axum_gate::{
    Account, Gate, Role, Group, JsonWebToken, JwtClaims,
    memory::{MemoryAccountRepository, MemorySecretRepository},
    AccountInsertService, AccessPolicy
};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Set up storage
    let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repo = Arc::new(MemorySecretRepository::default());

    // Create a test user
    AccountInsertService::insert("admin@example.com", "secure_password")
        .with_roles(vec![Role::Admin])
        .into_repositories(Arc::clone(&account_repo), Arc::clone(&secret_repo))
        .await
        .unwrap();

    // Set up JWT codec
    let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

    // Create cookie template
    let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-token", "")
        .secure(true)
        .http_only(true);

    // Build your application with protected routes
    let app = Router::<()>::new()
        .route("/admin", get(admin_handler))
        .layer(
            Gate::cookie_deny_all("my-app", Arc::clone(&jwt_codec))
                .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin))
                .with_cookie_template(cookie_template)
        )
        .route("/login", axum::routing::post(login_handler))
        .route("/logout", axum::routing::post(logout_handler));

    // Run your server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    //axum::serve(listener, app).await.unwrap();
}

async fn admin_handler() -> &'static str {
    "Admin access granted!"
}

// Login/logout handlers would use axum_gate::route_handlers::login/logout
async fn login_handler() -> &'static str { "Login endpoint" }
async fn logout_handler() -> &'static str { "Logout endpoint" }
```

## Access Control Options

### Role-Based Access

Grant access to specific roles:

```rust
use axum_gate::{AccessPolicy, Role, Group};

// Allow only Admin role
let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);

// Allow multiple roles
let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin)
    .or_require_role(Role::Moderator);
```

### Hierarchical Role Access

If your roles implement `AccessHierarchy`, you can grant access to a role and all its supervisors:

```rust
use axum_gate::{AccessPolicy, Role, Group};

// Allow User role and all supervisor roles (Reporter, Moderator, Admin)
let policy = AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User);
```

### Group-Based Access

Control access by user groups:

```rust
use axum_gate::{AccessPolicy, Role, Group};

// Allow specific groups
let policy = AccessPolicy::<Role, Group>::require_group(Group::new("engineering"))
    .or_require_group(Group::new("management"));
```

### Permission-Based Access

For fine-grained control, use the permission system:

```rust
use axum_gate::{AccessPolicy, PermissionId, Role, Group};

// Static permissions using compile-time validation
axum_gate::validate_permissions![
    "read:api",
    "write:api",
    "admin:system"
];

// Grant access based on permissions
let policy = AccessPolicy::<Role, Group>::require_permission(
    PermissionId::from("read:api")
);
```

## Working with User Data

Access authenticated user information in your handlers:

```rust
use axum::extract::Extension;
use axum_gate::{Account, Role, Group};

async fn profile_handler(
    Extension(user): Extension<Account<Role, Group>>
) -> String {
    format!(
        "Hello {}, your roles are {:?} and groups are {:?}",
        user.user_id, user.roles, user.groups
    )
}
```

## Account Management

Create and manage user accounts:

```rust
use axum_gate::{AccountInsertService, AccountDeleteService, Permissions, Role, Group};
use std::sync::Arc;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let account_repo = Arc::new(axum_gate::memory::MemoryAccountRepository::<Role, Group>::default());
# let secret_repo = Arc::new(axum_gate::memory::MemorySecretRepository::default());
// Create account with permissions
let permissions = Permissions::from_iter(["read:profile", "write:profile"]);

let account = AccountInsertService::insert("user@example.com", "password")
    .with_roles(vec![Role::User])
    .with_groups(vec![Group::new("staff")])
    .with_permissions(permissions)
    .into_repositories(account_repo.clone(), secret_repo.clone())
    .await?;

// Delete account
AccountDeleteService::delete(account.unwrap())
    .from_repositories(account_repo, secret_repo)
    .await?;
# Ok(())
# }
```

## Authentication Handlers

Use the built-in login and logout handlers:

```rust
use axum_gate::route_handlers::{login, logout};
use axum::{routing::post, Router, Json};
use axum_gate::{Credentials, RegisteredClaims, CookieJar};
use std::sync::Arc;

# let secret_repo = Arc::new(axum_gate::memory::MemorySecretRepository::default());
# let account_repo = Arc::new(axum_gate::memory::MemoryAccountRepository::<axum_gate::Role, axum_gate::Group>::default());
# let jwt_codec = Arc::new(axum_gate::JsonWebToken::default());
# let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-token", "");
let auth_routes = Router::<()>::new()
    .route("/login", post(|
        cookie_jar: CookieJar,
        Json(creds): Json<Credentials<String>>
    | async move {
        let registered_claims = RegisteredClaims::new("my-app",
            chrono::Utc::now().timestamp() as u64 + 3600); // 1 hour expiry

        login(
            cookie_jar,
            Json(creds),
            registered_claims,
            secret_repo,
            account_repo,
            jwt_codec,
            cookie_template.clone()
        ).await
    }))
    .route("/logout", post(|cookie_jar: CookieJar| async move {
        let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-token", "");
        logout(cookie_jar, cookie_template).await
    }));
```

## Permission Validation

### Compile-Time Validation

Ensure your permissions don't have conflicts at compile time:

```rust
use axum_gate::validate_permissions;

validate_permissions![
    "user:read:profile",
    "user:write:profile",
    "admin:manage:system",
    "admin:delete:user"
];
```

### Runtime Validation

For dynamic permissions loaded from configuration:

```rust
use axum_gate::ApplicationValidator;

# fn load_config_permissions() -> Vec<String> { vec![] }
# fn load_database_permissions() -> Vec<String> { vec![] }
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let report = ApplicationValidator::new()
    .add_permissions(load_config_permissions())
    .add_permissions(load_database_permissions())
    .add_permission("system:health")
    .validate()?;

if !report.is_valid() {
    return Err(format!("Permission validation failed: {}", report.summary()).into());
}
# Ok(())
# }
```

## Storage Implementations

### In-Memory Storage (Development/Testing)

```rust
use axum_gate::{Role, Group};
use axum_gate::memory::{MemoryAccountRepository, MemorySecretRepository};
use std::sync::Arc;

let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
let secret_repo = Arc::new(MemorySecretRepository::default());
```

### SurrealDB Storage (Feature: `storage-surrealdb`)

```rust
#[cfg(feature = "storage-surrealdb")]
use axum_gate::surrealdb::SurrealDbRepository;
#[cfg(feature = "storage-surrealdb")]
use axum_gate::{TableNames, surrealdb::DatabaseScope};
#[cfg(feature = "storage-surrealdb")]
use std::sync::Arc;

# #[cfg(feature = "storage-surrealdb")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let db = surrealdb::Surreal::new::<surrealdb::engine::remote::ws::Ws>("127.0.0.1:8000").await?;
# let table_names = TableNames::default();
# let scope = DatabaseScope {
#     table_names,
#     namespace: "axum_gate".to_string(),
#     database: "main".to_string(),
# };
# // SurrealDbRepository implements both AccountRepository and SecretRepository
# let repo = Arc::new(SurrealDbRepository::new(db, scope));
# Ok(())
# }
```

### SeaORM Storage (Feature: `storage-seaorm`)

```rust
#[cfg(feature = "storage-seaorm")]
use axum_gate::sea_orm::SeaOrmRepository;
#[cfg(feature = "storage-seaorm")]
use sea_orm::Database;
#[cfg(feature = "storage-seaorm")]
use std::sync::Arc;

# #[cfg(feature = "storage-seaorm")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let db = Database::connect("sqlite://./database.db").await?;
# // SeaOrmRepository implements both AccountRepository and SecretRepository
# let repo = Arc::new(SeaOrmRepository::new(&db));
# Ok(())
# }
```

## Custom Roles and Groups

Define your own roles and groups:

```rust
use axum_gate::AccessHierarchy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CustomRole {
    SuperAdmin,
    Admin,
    Manager,
    Employee,
    Guest,
}

impl std::fmt::Display for CustomRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl AccessHierarchy for CustomRole {
    fn supervisor(&self) -> Option<Self> {
        match self {
            Self::SuperAdmin => None,
            Self::Admin => Some(Self::SuperAdmin),
            Self::Manager => Some(Self::Admin),
            Self::Employee => Some(Self::Manager),
            Self::Guest => Some(Self::Employee),
        }
    }

    fn subordinate(&self) -> Option<Self> {
        match self {
            Self::SuperAdmin => Some(Self::Admin),
            Self::Admin => Some(Self::Manager),
            Self::Manager => Some(Self::Employee),
            Self::Employee => Some(Self::Guest),
            Self::Guest => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CustomGroup {
    name: String,
    department: String,
}

impl CustomGroup {
    fn new(name: &str, department: &str) -> Self {
        Self {
            name: name.to_string(),
            department: department.to_string(),
        }
    }
}
```

## Advanced Permission Management

### Zero-Synchronization Permission System

The permission system uses deterministic hashing to eliminate synchronization needs:

```rust
use axum_gate::Permissions;

# fn example() {
// Permissions are automatically available when referenced by name
let mut user_permissions = Permissions::new();

// Grant permissions - chainable API
user_permissions
    .grant("read:file")
    .grant("write:file")
    .grant("delete:file");

// Alternative: create from iterator
let user_permissions = Permissions::from_iter([
    "read:file",
    "write:file", 
    "delete:file"
]);

// Check permissions
if user_permissions.has("read:file") {
    println!("User can read files");
}

// Check multiple permissions
if user_permissions.has_all(["read:file", "write:file"]) {
    println!("User has all required permissions");
}

// Check any permission
if user_permissions.has_any(["delete:file", "admin:system"]) {
    println!("User can delete");
}
# }
```

### Runtime Permission Updates

```rust
use axum_gate::PermissionCollisionChecker;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
// For runtime permission validation
let dynamic_permissions = vec![
    "dynamic:feature1".to_string(),
    "dynamic:feature2".to_string()
];

let mut checker = PermissionCollisionChecker::new(dynamic_permissions);
let report = checker.validate()?;

if !report.is_valid() {
    eprintln!("Permission conflicts detected: {}", report.summary());
    // Handle conflicts appropriately for your application
}
# Ok(())
# }
```

## Error Handling

The crate provides comprehensive error types for different failure scenarios:

```rust
use axum_gate::errors::{Error, ApplicationError, InfrastructureError};

# async fn some_operation() -> Result<(), Error> { Ok(()) }
# async fn example() {
match some_operation().await {
    Ok(result) => { /* handle success */ },
    Err(Error::Application(app_error)) => {
        // Handle application-level errors (business logic failures)
        eprintln!("Application error: {}", app_error);
    },
    Err(Error::Infrastructure(infra_error)) => {
        // Handle infrastructure errors (database, JWT, etc.)
        eprintln!("Infrastructure error: {}", infra_error);
    },
    Err(Error::Port(port_error)) => {
        // Handle port adapter errors
        eprintln!("Port error: {}", port_error);
    }
    Err(_) => {
        // Handle any other error variants
        eprintln!("Other error occurred");
    }
}
# }
```

## Security Best Practices

1. **Use HTTPS**: Always set `secure(true)` on cookies in production
2. **HttpOnly Cookies**: Prevent XSS attacks with `http_only(true)`
3. **Strong Secrets**: Use long, random JWT signing keys
4. **Token Expiration**: Set appropriate expiration times for JWTs
5. **Permission Validation**: Always validate permissions at startup
6. **Separate Storage**: Keep account and secret data in separate storages when possible

```rust
// Production cookie configuration
let cookie_template = axum_gate::cookie::CookieBuilder::new("auth", "")
    .secure(true)      // HTTPS only
    .http_only(true)   // Prevent JavaScript access
    .same_site(axum_gate::cookie::SameSite::Strict)  // CSRF protection
    .max_age(axum_gate::cookie::time::Duration::hours(24)); // 24 hour expiry
```

## Examples

Check the `examples/` directory for complete working applications demonstrating:

- Custom roles and permissions
- Distributed system setup
- Database integration with SeaORM and SurrealDB
- Permission validation workflows

## License

This project is licensed under the **MIT** license.

See NOTICE file for dependency licenses.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in axum-gate by you shall be licensed as MIT, without any additional terms or conditions.
