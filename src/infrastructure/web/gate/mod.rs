//! Gate implementation for protecting axum routes with JWT cookie authentication.
//!
//! The `Gate` provides a high-level API for adding authentication and authorization
//! to your axum routes using JWT cookies. It supports role-based access control,
//! group-based access control, and fine-grained permission systems.
//!
//! # Basic Usage
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use axum_gate::auth::{AccessPolicy, Role, Group, Account};
//! use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! use axum_gate::prelude::Gate;
//! use axum_gate::prelude::CookieTemplateBuilder;
//! use std::sync::Arc;
//!
//! # async fn protected_handler() -> &'static str { "Protected!" }
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let cookie_template = CookieTemplateBuilder::recommended()
//!     .name("auth-token")
//!     .persistent(cookie::time::Duration::hours(24))
//!     .build();
//!
//! let app = Router::<()>::new()
//!     .route("/admin", get(protected_handler))
//!     .layer(
//!         Gate::cookie("my-app", jwt_codec)
//!             .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin))
//!             .with_cookie_template(cookie_template)
//!     );
//! ```
//!
//! # Access Control Examples
//!
//! ## Role-Based Access
//! ```rust
//! # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
//! # use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! # use axum_gate::prelude::Gate;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! # let cookie_template = cookie::CookieBuilder::new("auth", "");
//! // Allow only Admin role
//! let gate = Gate::cookie("my-app", Arc::clone(&jwt_codec))
//!     .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
//!
//! // Allow Admin or Moderator roles
//! let gate = Gate::cookie("my-app", Arc::clone(&jwt_codec))
//!     .with_policy(
//!         AccessPolicy::<Role, Group>::require_role(Role::Admin)
//!             .or_require_role(Role::Moderator)
//!     );
//! ```
//!
//! ## Hierarchical Access
//! ```rust
//! # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
//! # use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! # use axum_gate::prelude::Gate;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! // Allow User role and all supervisor roles (Reporter, Moderator, Admin)
//! let gate = Gate::cookie("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::<Role, Group>::require_role_or_supervisor(Role::User));
//! ```
//!
//! ## Permission-Based Access
//! ```rust
//! # use axum_gate::auth::{AccessPolicy, Role, Group, Account, PermissionId};
//! # use axum_gate::jwt::{JsonWebToken, JwtClaims};
//! # use axum_gate::prelude::Gate;
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie("my-app", jwt_codec)
//!     .with_policy(
//!         AccessPolicy::<Role, Group>::require_permission(PermissionId::from("read:api"))
//!     );
//! ```
use crate::domain::traits::AccessHierarchy;
use crate::ports::Codec;
use cookie::CookieGate;

use std::sync::Arc;

pub mod bearer;
pub mod cookie;

/// Main entry point for creating authentication gates.
///
/// Gates protect your axum routes from unauthorized access using JWT cookies.
/// All requests are denied by default unless explicitly granted access through
/// an access policy.
#[derive(Clone)]
pub struct Gate;

impl Gate {
    /// Creates a new cookie-based gate that denies all access by default.
    ///
    /// Attach an access policy using `with_policy()` to grant access. This secure-by-default
    /// approach ensures no routes are exposed until you explicitly configure a policy.
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
    /// # use axum_gate::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::Gate;
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let policy = AccessPolicy::<Role, Group>::require_role(Role::Admin);
    ///
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(policy);
    /// ```
    pub fn cookie<C, R, G>(issuer: &str, codec: Arc<C>) -> CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + std::fmt::Display,
        G: Eq,
    {
        CookieGate::new_with_codec(issuer, codec)
    }

    /// Creates a new bearer-header based gate that denies all access by default.
    ///
    /// This variant protects routes by expecting an `Authorization: Bearer <token>`
    /// header. Missing or invalid bearer tokens result in `401 Unauthorized`.
    ///
    /// Like the cookie-based gate, it will support (once implemented) an
    /// `allow_anonymous_with_optional_user()` (or similarly named) configuration
    /// method to install `Option<Account<R,G>>` / `Option<RegisteredClaims>` in
    /// request extensions without enforcing authorization (mirroring the cookie
    /// gate's anonymous optional mode).
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    pub fn bearer<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
    ) -> bearer::BearerGate<C, R, G, bearer::JwtConfig<R, G>>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq + Clone,
    {
        // Delegates to the BearerGate builder (to be implemented in bearer module).
        bearer::BearerGate::new_with_codec(issuer, codec)
    }
}
