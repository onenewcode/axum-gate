Fully customizable role based JWT cookie auth for axum, applicable for single nodes or distributed systems.

`axum-gate` uses composition of different services to enable maximum flexibility
for any specific use case. It provides a high-level API for role based access within `axum`. Encryption/encoding is outsourced to external crates.

# Features

- Role based access auth for `axum` using JWT cookies
- Support for custom roles
- Support for custom groups
- Can be used in single nodes and/or distributed systems
- Separate storage of `Account` and `Secret` information for increased security
- Support for `surrealdb`, `sea-orm` and `memory` storages
- Pre-defined handler for fast and easy integration
- Static permission set for fine-grained resource control
- Dynamic permission set for resource control that changes during runtime
- Runtime validation for permission collision checking with detailed error reporting

## Planned features

- Simple to use Bearer auth layer with support for rotating key set or using a custom function
  (for node to node authentication, see
  [DynamicPermissionService](crate::services::DynamicPermissionService))

# Introduction

To protect your application with `axum-gate` you need to use storages that implement
[SecretRepository](crate::ports::repositories::SecretRepository),
[CredentialsVerifier](crate::ports::auth::CredentialsVerifier) and
[AccountRepository](crate::ports::repositories::AccountRepository). It is possible to implement
all on the same storage if it is responsible
for [`Account`] as well as the [`Secret`](crate::secrets::Secret) of a user.
See [storage] module for pre-implemented storages.

The basic process of initialization and usage of a storage is independent of the actual used storage
implementation. For demonstration purposes, we will use
[MemoryAccountStorage](crate::storage::memory::MemoryAccountStorage)
and [MemorySecretStorage](crate::storage::memory::MemorySecretStorage) implementation.

# Protecting your application

After creating the connections to the storages, the actual protection of your application is pretty
simple. When protecting with a `Gate`, all requests are denied by default. All grant possibilities
presented below can also be combined so you are not limited to choosing one.

## Limit access to a specific role

You can limit the access of a route to one or multiple specific role(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Role, Group};
# use axum_gate::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn admin() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route(
        "/admin",
        // Please note, that the layer is applied directly to the route handler.
        get(admin).layer(
            Gate::new_cookie("my-issuer-id", Arc::clone(&jwt_codec))
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
# use axum_gate::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn user() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route("/user", get(user))
    // In contrast to granting access to user only, this layer is applied to the route.
    .layer(
        Gate::new_cookie("my-issuer-id", Arc::clone(&jwt_codec))
            .with_cookie_template(cookie_template)
            .grant_role_and_supervisor(Role::User)
    );
```

## Grant access to a group of users

You can limit the access of a route to one or more specific group(s).

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Group, Role};
# use axum_gate::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
# async fn group_handler() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route(
        "/group-scope",
        // Please note, that the layer is applied directly to the route handler.
        get(group_handler).layer(
            Gate::new_cookie("my-issuer-id", Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_group(Group::new("my-group"))
                .grant_group(Group::new("another-group"))
        )
    );
```

## Use permissions to refine resource control

If a basic role/group access model does not match your use case or you need precise
access control for your endpoints, you can use permissions. There are two separate ways to use
permissions for fine-grained resource control, static and
[dynamic](crate::services::DynamicPermissionService).

If your resources do not change over time, the following example should fit your use case.

```rust
# use axum::routing::{Router, get};
# use axum_gate::{Account, Gate, Group, Role};
# use axum_gate::{JsonWebToken, JwtClaims};
# use std::sync::Arc;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
#[non_exhaustive]
enum MyCustomPermission {
    ReadApi,
    WriteApi,
}

# async fn read_api_handler() -> () {}
# let jwt_codec: Arc<JsonWebToken<JwtClaims<Account<Role, Group>>>> = Arc::new(JsonWebToken::default());
let cookie_template = axum_gate::cookie::CookieBuilder::new("axum-gate", "").secure(true);
let app = Router::<Gate>::new()
    .route(
        "/read-api",
        // Please note, that the layer is applied directly to the route handler.
        get(read_api_handler).layer(
            Gate::new_cookie("my-issuer-id", Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template)
                .grant_permission(MyCustomPermission::ReadApi)
              // or use:
              //.grant_permissions(vec![MyCustomPermission::ReadApi])
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
        user.user_id, user.roles, user.groups
    ))
}
```

# Handling storage of `Account`s and `Secret`s

You can use the [AccountInsertService](crate::application::accounts::AccountInsertService) and
[AccountDeleteService](crate::application::accounts::AccountDeleteService) for easy insertion and deletion
of user accounts and their secrets.

```rust
# use axum_gate::{Account, Role, Group};
# use axum_gate::Secret;
# use axum_gate::Argon2Hasher;
# use axum_gate::memory::{MemorySecretRepository, MemoryAccountRepository};
# use axum_gate::{AccountInsertService, AccountDeleteService};
# use std::sync::Arc;
# async fn example_storage() {
// We first instantiate both memory storages.
let acc_store = Arc::new(MemoryAccountRepository::from(Vec::<Account<Role, Group>>::new()));
let sec_store = Arc::new(MemorySecretRepository::from(Vec::<Secret>::new()));

// The AccountInsertService provides an ergonomic way of inserting the account into the repositories.
let user_account = AccountInsertService::insert("user@example.com", "my-user-password")
    .with_roles(vec![Role::User])
    .into_repositories(Arc::clone(&acc_store), Arc::clone(&sec_store))
    .await
    .unwrap()
    .unwrap();

/// You can also remove a combination of account and secret using the AccountDeleteService.
AccountDeleteService::delete(user_account)
    .from_repositories(Arc::clone(&acc_store), Arc::clone(&sec_store))
    .await
    .unwrap();
# }
```

# Enable login and logout for your application

`axum-gate` provides pre-defined [route_handler](crate::route_handlers) for login and logout
using [Credentials].

# Permission Validation

For applications with variable permission strings, `axum-gate` provides comprehensive validation capabilities:

## Compile-time Validation

Use the `validate_permissions!` macro with enhanced error reporting:

```rust
use axum_gate::validate_permissions;

validate_permissions![
    "user:read:profile",
    "user:write:profile",
    "admin:manage:system"
];
```

If there are duplicates or hash collisions, you'll get detailed error messages showing all permissions being validated:

```text,no_run
Duplicate permission name found in: ["user:read", "admin:write", "user:read"].
All permission names must be unique. Check for duplicate entries and remove or rename them.
```

## Runtime Validation

For dynamic permissions loaded from configuration:

```rust
use axum_gate::{ApplicationValidator, PermissionCollisionChecker, ValidationReport};
use tracing::error;

// Permission conflicts handler
fn handle_permission_conflicts(report: &ValidationReport) {}

let config_permissions = ["user:read", "admin:write"];
let dynamic_permissions = ["dynamic:access"];

// Application startup validation
let report = ApplicationValidator::new()
    .add_permissions(config_permissions)
    .add_permissions(dynamic_permissions)
    .validate()
    .expect("Validation failed.");

if !report.is_valid() {
    error!("Permission validation failed: {}", report.summary());
    return;
}

let updated_permissions = ["dynamic:updated", "user:read"]
    .iter()
    .map(|s| s.to_string())
    .collect::<Vec<String>>();

// Runtime validation during application events
let mut checker = PermissionCollisionChecker::new(updated_permissions);
let report = checker.validate().expect("Runtime validation failed.");
if !report.is_valid() {
    // Handle validation issues appropriately
    handle_permission_conflicts(&report);
}
```

The validation system provides:
- Duplicate string detection
- Hash collision detection (extremely rare but possible)
- Detailed reporting for debugging
- Flexible error handling (no panics in runtime validation)
- Zero overhead once validation completes

# Permission Validation

For applications with variable permission strings, `axum-gate` provides runtime validation
capabilities to check for permission duplicates and hash collisions:

```rust
use axum_gate::ApplicationValidator;

// Application startup validation
let report = ApplicationValidator::new()
    .add_permissions(["user:read", "user:write"])
    .add_permission("admin:delete")
    .validate()?;

if !report.is_valid() {
    return Err(anyhow::anyhow!("Permission validation failed: {}", report.summary()));
}
# Ok::<(), anyhow::Error>(())
```

This complements the compile-time validation provided by [`validate_permissions!`]
and is particularly useful for dynamic permission strings loaded from configuration
files or generated at runtime.

# License
This project is licensed under the **MIT** license.

See NOTICE file for dependency licenses.

# Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in axum-gate by you, shall be licensed as MIT, without any additional terms or conditions.
