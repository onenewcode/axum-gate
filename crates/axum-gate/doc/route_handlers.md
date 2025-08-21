## Login

To enable a login, you only need to add a custom route with the
[login](crate::route_handlers::login) handler.

```rust
# use axum::extract::Json;
# use axum::routing::{Router, post};
# use axum_gate::Credentials;
# use axum_gate::jwt::{JsonWebToken, RegisteredClaims};
# use axum_gate::{Account, Gate, Role, Group};
# use axum_gate::hashing::Argon2Hasher;
# use axum_gate::secrets::Secret;
# use axum_gate::storage::memory::{MemorySecretStorage, MemoryAccountStorage};
# use std::sync::Arc;
# use chrono::{Utc, TimeDelta};
let account_storage = Arc::new(MemoryAccountStorage::from(Vec::<Account<Role, Group>>::new()));
let secret_storage = Arc::new(MemorySecretStorage::from(Vec::<Secret>::new()));
# let jwt_codec = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route(
        "/login",
        post({
            let registered_claims = RegisteredClaims::new(
                "my-auth-node-issuer-id", // iss claim in the JWT
                (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64, // exp in the JWT
            );
            let credentials_verifier = Arc::clone(&secret_storage);
            let account_storage = Arc::clone(&account_storage);
            let jwt_codec = Arc::clone(&jwt_codec);
            let cookie_template = cookie_template.clone();
            move |cookie_jar, request_credentials: Json<Credentials<String>>| {
                axum_gate::route_handlers::login(
                    cookie_jar,
                    request_credentials,
                    registered_claims,
                    credentials_verifier,
                    account_storage,
                    jwt_codec,
                    cookie_template,
                )
            }
        }),
    );
```

## Logout

Because `axum-gate` is using a cookie to store the information, you can easily create a logout
route:
```rust
# use axum_gate::{Role, Account, Gate, Group};
# use axum_gate::jwt::JsonWebToken;
# use axum_gate::route_handlers;
# use axum::{routing::get, Router};
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route(
        "/logout",
        get({
            move |cookie_jar| {
                route_handlers::logout(cookie_jar, cookie_template)
            }
        })
    );
```

## Zero-Sync Permission System

The permission system now uses deterministic hashing for zero-synchronization across distributed
systems. No coordination between nodes is required - permissions work instantly everywhere.

### Using Permissions in Your Application

```rust
# use axum_gate::{permissions::{PermissionChecker, PermissionId}, validate_permissions};
# use roaring::RoaringBitmap;

// 1. Validate permissions at compile time
validate_permissions![
    "read:resource1",
    "write:resource1",
    "read:resource2",
    "admin:system"
];

// 2. Grant permissions to users
let mut user_permissions = RoaringBitmap::new();
PermissionChecker::grant_permission(&mut user_permissions, "read:resource1");
PermissionChecker::grant_permission(&mut user_permissions, "write:resource1");

// 3. Check permissions in route handlers
if PermissionChecker::has_permission(&user_permissions, "read:resource1") {
    // Grant access
}

// 4. Use with Gates
# use axum_gate::{Role, Account, Gate, Group};
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# use axum::{routing::get, Router};
# let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
# let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<()>::new()
    .route("/protected", get(protected_handler))
    .layer(
        Gate::new_cookie("issuer", jwt_codec)
            .with_cookie_template(cookie_template)
            .grant_permission(PermissionId::from_name("read:resource1"))
    );

async fn protected_handler() -> &'static str {
    "Access granted!"
}
```
