## Login

To enable a login, you only need to add a custom route with the
[login](crate::route_handlers::login) handler.

```rust
# use axum::extract::Json;
# use axum::routing::{Router, post};
# use axum_gate::Credentials;
# use axum_gate::{JsonWebToken, RegisteredClaims};
# use axum_gate::{Account, Gate, Role, Group};
# use axum_gate::{Argon2Hasher, Secret};
# use axum_gate::memory::{MemorySecretRepository, MemoryAccountRepository};
# use std::sync::Arc;
# use chrono::{Utc, TimeDelta};
let account_storage = Arc::new(MemoryAccountRepository::from(Vec::<Account<Role, Group>>::new()));
let secret_storage = Arc::new(MemorySecretRepository::from(Vec::<Secret>::new()));
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
# use axum_gate::JsonWebToken;
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
