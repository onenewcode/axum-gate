Fully customizable role based JWT cookie auth for axum, applicable for single nodes or distributed systems.

`axum-gate` uses composition of different services to enable maximum flexibility
for any specific use case.

# Security considerations

This crate has not been audited by third party security experts. This software MAY have security
issues that have not been detected yet. If you found one, please
[file an issue](https://github.com/emirror-de/axum-gate/issues/new?title=Vulnerability%20detected&labels=security,bug).
The authors do not guarantee the security nor are liable for
any type of issues within the use of this software.

# Examples

These examples aim to give you a basic overview about the possibilities that [axum-gate](crate) offers.

## Prerequisites to protect your application

To protect your application with `axum-gate` you need to use storages that implement
[CredentialsStorageService](crate::storage::CredentialsStorageService),
[CredentialsVerifierService](crate::credentials::CredentialsVerifierService) and
[PassportStorageService](crate::storage::PassportStorageService). It is possible to implement
all on the same storage if it is responsible
for [`Passport`](crate::passport::Passport) as well as the
[`Credentials`](crate::credentials::Credentials) of a user.

In case of the pre-defined [MemoryPassportStorage](crate::storage::memory::MemoryPassportStorage)
and [CredentialsMemoryStorage](crate::storage::memory::MemoryCredentialsStorage)
(implements both, [CredentialsStorageService](crate::storage::CredentialsStorageService) and
[CredentialsVerifierService](crate::credentials::CredentialsVerifierService))
, the following steps are required during the setup of your app. The pre-defined storages
use the memory to store the information.

```rust
# use axum_gate::credentials::Credentials;
# use axum_gate::Account;
# use axum_gate::roles::BasicRole;
# use axum_gate::secrets::Argon2Hasher;
# use axum_gate::storage::memory::{MemoryCredentialsStorage, MemoryPassportStorage};
# use std::sync::Arc;
# async fn example_storage() {
// We first need to create the credentials.
// For demonstration purpose only, your application should provide another way to add
// credentials.
let user_creds = Credentials::new(
    "user@example.com",
    "user_password",
);
// Then a credentials storage is created.
let creds_storage = MemoryCredentialsStorage::try_from(vec![user_creds.clone()]).unwrap();
// Same for the passport which provides details about the user.
// The ID is used to create a connection between the storage entries.
let user_passport = Account::new(&user_creds.id, &["user"], &[BasicRole::User])
    .expect("Creating passport failed.");
let passport_storage = MemoryPassportStorage::from(vec![user_passport]);
# }
```

## Protecting your application

The actual protection of your application is pretty simple. All possibilities presented below
can also be combined so you are not limited to choosing one.

### Limit access to a specific role

You can limit the access of a route to one or multiple specific role(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::Gate;
# use axum_gate::roles::BasicRole;
# use axum_gate::Account;
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn admin() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<String>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<Account<String>, JsonWebToken<Account<String>>>>::new()
    .route(
        "/admin",
        // Please note, that the layer is applied directly to the route handler.
        get(admin).layer(
            Gate::new(Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_role(BasicRole::Admin)
                .grant_role(BasicRole::User)
        )
    );
```

### Grant access to a specific role and all its supervisors

If your role implements [AccessHierarchy], you can limit the access of a route to a specific role but at the same time allow it to
all supervisor of this role. This is also possible for multiple roles, although this does not
make much sense in a real world application.

```rust
# use axum::routing::{Router, get};
# use axum_gate::Gate;
# use axum_gate::roles::BasicRole;
# use axum_gate::Account;
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn user() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<String>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<Account<String>, JsonWebToken<Account<String>>>>::new()
    .route("/user", get(user))
    // In contrast to granting access to user only, this layer is applied to the route.
    .layer(
        Gate::new(Arc::clone(&jwt_codec))
            .with_cookie_template(cookie_template)
            .grant_role_and_supervisor(BasicRole::User)
    );
```

### Grant access to a group of users

You can limit the access of a route to one or more specific group(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::Gate;
# use axum_gate::Account;
# use axum_gate::Group;
# use axum_gate::jwt::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn group_handler() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<String>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<Account<String>, JsonWebToken<Account<String>>>>::new()
    .route(
        "/group-scope",
        // Please note, that the layer is applied directly to the route handler.
        get(group_handler).layer(
            Gate::new(Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_group(Group::new("my-group"))
                .grant_group(Group::new("another-group"))
        )
    );
```

## Using `Passport` details in your route handler

`axum-gate` provides two [Extension](axum::extract::Extension)s to the handler.
The first one contains the [RegisteredClaims](crate::jwt::RegisteredClaims), the second
your custom claims. In this pre-defined case it is the
[`Account`](crate::Account).
You can use them like any other extension:
```rust
# use axum::extract::Extension;
# use axum_gate::Account;
async fn reporter(Extension(user): Extension<Account<String>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {}, your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}
```

## Enable login and logout for your application

`axum-gate` provides pre-defined [route_handler](crate::route_handlers) for login and logout
using [Credentials](crate::credentials::Credentials).

### Login

To enable a login, you only need to add a custom route with the
[login](crate::route_handlers::login) handler.

```rust
# use axum::extract::Json;
# use axum::routing::{Router, post};
# use axum_gate::credentials::Credentials;
# use axum_gate::jwt::{JsonWebToken, RegisteredClaims};
# use axum_gate::Gate;
# use axum_gate::Account;
# use axum_gate::secrets::Argon2Hasher;
# use axum_gate::storage::memory::{MemoryCredentialsStorage, MemoryPassportStorage};
# use std::sync::Arc;
# let creds_storage = Arc::new(MemoryCredentialsStorage::<String, Argon2Hasher>::try_from(vec![]).unwrap());
# let passport_storage = Arc::new(MemoryPassportStorage::<Account<String>>::from(vec![]));
# let jwt_codec = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
// let app = Router::new() is enough in the real world, this long type is to satisfy compiler.
let app = Router::<Gate<Account<String>, JsonWebToken<Account<String>>>>::new()
    .route(
        "/login",
        post({
            let registered_claims = RegisteredClaims::default();
            let credentials_verifier = Arc::clone(&creds_storage);
            let passport_storage = Arc::clone(&passport_storage);
            let jwt_codec = Arc::clone(&jwt_codec);
            let cookie_template = cookie_template.clone();
            move |cookie_jar, request_credentials: Json<Credentials<String>>| {
                axum_gate::route_handlers::login(
                    cookie_jar,
                    request_credentials,
                    registered_claims,
                    credentials_verifier,
                    passport_storage,
                    jwt_codec,
                    cookie_template,
                )
            }
        }),
    );
```

### Logout

Because `axum-gate` is using a cookie to store the information, you can easily create a logout
route:
```rust,ignore
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::new()
    .get({
        move |cookie_jar| {
            axum_gate::route_handlers::logout(cookie_jar, cookie_template)
        }
    });
```

# Internal examples
- A pre-defined implementation of [SecretsHashingService](crate::secrets::SecretsHashingService)
can be found at [Argon2Hasher](crate::secrets::Argon2Hasher) that is used to hash credentials
before persisting it using [CredentialsStorageService](crate::storage::CredentialsStorageService)
- An example for a [CredentialsStorageService](crate::storage::CredentialsStorageService) /
[CredentialsVerifierService](crate::credentials::CredentialsVerifierService) used for
authentication can be found at [MemoryCredentialsStorage](crate::storage::memory::MemoryCredentialsStorage)

# License
This project is licensed under the **MIT** license.

# Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in axum-gate by you, shall be licensed as MIT, without any additional terms or conditions.
