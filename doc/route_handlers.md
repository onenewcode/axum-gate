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
// let app = Router::new() is enough in the real world, this long type is to satisfy the compiler
// for this example.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
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
// let app = Router::new() is enough in the real world, this long type is to satisfy the compiler
// for this example.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
    .route(
        "/logout",
        get({
            move |cookie_jar| {
                route_handlers::logout(cookie_jar, cookie_template)
            }
        })
    );
```

## Dynamic permission set

There is also a pre-defined handler available for updating a dynamic permission set within your
application.

It can be used on distributed systems and enables creating a single source of truth
for the permission set that is able to update all other nodes on demand. When using this handler,
make sure that you also protect it properly.
```rust
# use axum_gate::{Role, Account, Gate, Group, PermissionSet};
# use axum_gate::jwt::JsonWebToken;
# use axum_gate::route_handlers;
# use std::sync::Arc;
# use axum::{routing::patch, Router};
let permission_set = Arc::new(PermissionSet::new(vec![
    "read:resource1".to_string(),
    "read:resource2".to_string()
]));
// let app = Router::new() is enough in the real world, this long type is to satisfy the compiler
// for this example.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
    .route(
        "/extend-permissions",
        patch({
            move |updated_permission_set| {
                route_handlers::extend_permission_set(updated_permission_set, Arc::clone(&permission_set))
            }
        })
    );
```
