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
//! use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
//! use std::sync::Arc;
//!
//! # async fn protected_handler() -> &'static str { "Protected!" }
//! let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let cookie_template = cookie::CookieBuilder::new("auth-token", "")
//!     .secure(true)
//!     .http_only(true);
//!
//! let app = Router::new()
//!     .route("/admin", get(protected_handler))
//!     .layer(
//!         Gate::cookie_deny_all("my-app", jwt_codec)
//!             .with_policy(AccessPolicy::require_role(Role::Admin))
//!             .with_cookie_template(cookie_template)
//!     );
//! ```
//!
//! # Access Control Examples
//!
//! ## Role-Based Access
//! ```rust
//! # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! # let cookie_template = cookie::CookieBuilder::new("auth", "");
//! // Allow only Admin role
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::require_role(Role::Admin));
//!
//! // Allow Admin or Moderator roles
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(
//!         AccessPolicy::require_role(Role::Admin)
//!             .or_require_role(Role::Moderator)
//!     );
//! ```
//!
//! ## Hierarchical Access
//! ```rust
//! # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! // Allow User role and all supervisor roles (Reporter, Moderator, Admin)
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(AccessPolicy::require_role_or_supervisor(Role::User));
//! ```
//!
//! ## Permission-Based Access
//! ```rust
//! # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account, PermissionId};
//! # use std::sync::Arc;
//! # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//! let gate = Gate::cookie_deny_all("my-app", jwt_codec)
//!     .with_policy(
//!         AccessPolicy::require_permission(PermissionId::from_name("read:api"))
//!     );
//! ```
use self::cookie_service::CookieGateService;
use crate::cookie::CookieBuilder;
use crate::domain::services::access_policy::AccessPolicy;
use crate::domain::traits::AccessHierarchy;
use crate::ports::Codec;

use std::sync::Arc;

use tower::Layer;

mod cookie_service;

/// Main entry point for creating authentication gates.
///
/// Gates protect your axum routes from unauthorized access using JWT cookies.
/// All requests are denied by default unless explicitly granted access through
/// an access policy.
#[derive(Clone)]
pub struct Gate;

impl Gate {
    /// Creates a new cookie-based gate with the specified access policy.
    ///
    /// This is the low-level constructor that requires you to provide a complete
    /// access policy. Most users should prefer `cookie_deny_all()` with `with_policy()`.
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    /// * `policy` - Access policy defining who can access protected routes
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let policy = AccessPolicy::require_role(Role::Admin);
    ///
    /// let gate = Gate::cookie("my-app", jwt_codec, policy);
    /// ```
    pub fn cookie<C, R, G>(
        issuer: &str,
        codec: Arc<C>,
        policy: AccessPolicy<R, G>,
    ) -> CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq,
    {
        CookieGate {
            issuer: issuer.to_string(),
            policy,
            codec,
            cookie_template: CookieBuilder::new("axum-gate", ""),
        }
    }

    /// Creates a new cookie-based gate that denies all access by default.
    ///
    /// This is the recommended way to create gates. It follows a secure-by-default
    /// approach where no access is granted until you explicitly configure an access policy.
    ///
    /// # Arguments
    /// * `issuer` - The JWT issuer identifier for your application
    /// * `codec` - JWT codec for encoding/decoding tokens
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    ///
    /// let gate = Gate::cookie_deny_all("my-app", jwt_codec)
    ///     .with_policy(AccessPolicy::require_role(Role::Admin))
    ///     .with_cookie_template(
    ///         cookie::CookieBuilder::new("auth-token", "")
    ///             .secure(true)
    ///             .http_only(true)
    ///     );
    /// ```
    pub fn cookie_deny_all<C, R, G>(issuer: &str, codec: Arc<C>) -> CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq,
    {
        Self::cookie(issuer, codec, AccessPolicy::deny_all())
    }
}

/// A configured gate ready to be used as an axum layer.
///
/// This struct is created by `Gate::cookie()` or `Gate::cookie_deny_all()` and can be
/// customized with `with_policy()` and `with_cookie_template()` before being applied
/// as a layer to your routes.
#[derive(Clone)]
pub struct CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    issuer: String,
    policy: AccessPolicy<R, G>,
    codec: Arc<C>,
    cookie_template: CookieBuilder<'static>,
}

impl<C, R, G> CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Sets the access policy for this gate.
    ///
    /// The access policy defines who has access to the protected routes. Access is granted
    /// if the authenticated user meets ANY of the policy requirements (OR logic).
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie_deny_all("my-app", jwt_codec)
    ///     .with_policy(
    ///         AccessPolicy::require_role(Role::Admin)
    ///             .or_require_role(Role::Moderator)
    ///             .or_require_group(Group::new("emergency-access"))
    ///     );
    /// ```
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.policy = policy;
        self
    }

    /// Configures the cookie template used for authentication.
    ///
    /// The cookie template defines how authentication cookies are created, including
    /// their name, security settings, and expiration. For production use, ensure
    /// cookies are configured securely.
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::{Gate, AccessPolicy, Role, Group, JsonWebToken, JwtClaims, Account};
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let cookie_template = cookie::CookieBuilder::new("auth-token", "")
    ///     .secure(true)      // HTTPS only
    ///     .http_only(true)   // Prevent XSS
    ///     .same_site(cookie::SameSite::Strict)  // CSRF protection
    ///     .max_age(cookie::time::Duration::hours(24)); // 24 hour expiry
    ///
    /// let gate = Gate::cookie_deny_all("my-app", jwt_codec)
    ///     .with_cookie_template(cookie_template);
    /// ```
    pub fn with_cookie_template(mut self, template: CookieBuilder<'static>) -> Self {
        self.cookie_template = template;
        self
    }
}

impl<S, C, R, G> Layer<S> for CookieGate<C, R, G>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    type Service = CookieGateService<C, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieGateService::new(
            inner,
            &self.issuer,
            self.policy.clone(),
            Arc::clone(&self.codec),
            self.cookie_template.clone(),
        )
    }
}
