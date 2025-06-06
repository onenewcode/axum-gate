Fully customizable role based JWT cookie auth for axum, applicable for single nodes or distributed systems.

`axum-gate` uses composition of different services to enable maximum flexibility
for any specific use case. It provides a high-level API for role based access within `axum`. Encryption/encoding is outsourced to external crates.

# Security considerations

This crate has not been audited by third party security experts. This software MAY have security
issues that have not been detected yet. If you found one, please
[file an issue](https://github.com/emirror-de/axum-gate/issues/new?title=Vulnerability%20detected&labels=security,bug).
The authors do not guarantee the security nor are liable for
any type of issues within the use of this software.

# Introduction

To protect your application with `axum-gate` you need to use storages that implement
[SecretStorageService](crate::services::SecretStorageService),
[CredentialsVerifierService](crate::services::CredentialsVerifierService) and
[AccountStorageService](crate::services::AccountStorageService). It is possible to implement
all on the same storage if it is responsible
for [`Account`] as well as the [`Secret`](crate::secrets::Secret) of a user.

The basic process of initialization and usage of a storage is independent of the actual used storage
implementation. For demonstration purposes, we will use
[MemoryAccountStorage](crate::storage::memory::MemoryAccountStorage)
and [MemorySecretStorage](crate::storage::memory::MemorySecretStorage) implementation.

# Insertion and deletion of `Account`s and `Secret`s

You can use the [AccountInsertService](crate::services::AccountInsertService) and
[AccountDeleteService](crate::services::AccountDeleteService) for easy insertion and deletion
of user accounts and their secrets.

```rust
# use axum_gate::{Account, Role, Group};
# use axum_gate::secrets::Secret;
# use axum_gate::hashing::Argon2Hasher;
# use axum_gate::storage::memory::{MemorySecretStorage, MemoryAccountStorage};
# use axum_gate::services::{AccountInsertService, AccountDeleteService};
# use std::sync::Arc;
# async fn example_storage() {
// We first instantiate both memory storages.
let acc_store = Arc::new(MemoryAccountStorage::from(Vec::<Account<Role, Group>>::new()));
let sec_store = Arc::new(MemorySecretStorage::from(Vec::<Secret>::new()));

// The AccountInsertService provides an ergonomic way of inserting the account into the storages.
let user_account = AccountInsertService::insert("user@example.com", "my-user-password")
    .with_roles(vec![Role::User])
    .with_groups(vec![Group::new("staff")])
    .into_storages(Arc::clone(&acc_store), Arc::clone(&sec_store))
    .await
    .unwrap()
    .unwrap();

/// You can also remove a combination of account and secret using the AccountDeleteService.
AccountDeleteService::delete(user_account)
    .from_storages(Arc::clone(&acc_store), Arc::clone(&sec_store))
    .await
    .unwrap();
# }
```

# Protecting your application

After creating the connections to the storages, the actual protection of your application is pretty
simple. All possibilities presented below can also be combined so you are not limited to choosing
one.

## Limit access to a specific role

You can limit the access of a route to one or multiple specific role(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Role, Group};
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn admin() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
    .route(
        "/admin",
        // Please note, that the layer is applied directly to the route handler.
        get(admin).layer(
            Gate::new("my-issuer-id", Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_role(Role::Admin)
                .grant_role(Role::User)
        )
    );
```

## Grant access to a specific role and all its supervisors

If your role implements [AccessHierarchy](crate::utils::AccessHierarchy), you can limit the access
of a route to a specific role
but at the same time allow it to all supervisor of this role. This is also possible for multiple
roles, although this does not make much sense in a real world application.

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Role, Group};
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn user() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
    .route("/user", get(user))
    // In contrast to granting access to user only, this layer is applied to the route.
    .layer(
        Gate::new("my-issuer-id", Arc::clone(&jwt_codec))
            .with_cookie_template(cookie_template)
            .grant_role_and_supervisor(Role::User)
    );
```

## Grant access to a group of users

You can limit the access of a route to one or more specific group(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Group, Role};
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn group_handler() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<JsonWebToken<Account<Role, Group>>, Role, Group>>::new()
    .route(
        "/group-scope",
        // Please note, that the layer is applied directly to the route handler.
        get(group_handler).layer(
            Gate::new("my-issuer-id", Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_group(Group::new("my-group"))
                .grant_group(Group::new("another-group"))
        )
    );
```

# Using `Account` details in your route handler

`axum-gate` provides two [Extension](axum::extract::Extension)s to the handler.
The first one contains the [RegisteredClaims](crate::jwt::RegisteredClaims), the second
your custom claims. In this pre-defined case it is the
[`Account`].
You can use them like any other extension:
```rust
# use axum::extract::Extension;
# use axum_gate::{Account, Role, Group};
async fn reporter(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {}, your roles are {:?} and you are member of groups {:?}!",
        user.account_id, user.roles, user.groups
    ))
}
```

# Enable login and logout for your application

`axum-gate` provides pre-defined [route_handler](crate::route_handlers) for login and logout
using [Credentials].

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

# License
This project is licensed under the **MIT** license.

# Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in axum-gate by you, shall be licensed as MIT, without any additional terms or conditions.
