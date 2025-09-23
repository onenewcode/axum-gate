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
use self::cookie_service::CookieGateService;
use crate::domain::services::access_policy::AccessPolicy;
use crate::domain::traits::AccessHierarchy;
use crate::http::cookie::CookieBuilder;
use crate::infrastructure::web::cookie_template::CookieTemplateBuilder;
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
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq,
    {
        CookieGate {
            issuer: issuer.to_string(),
            policy: AccessPolicy::deny_all(),
            codec,
            cookie_template: CookieTemplateBuilder::recommended().build(),
        }
    }
}

/// A configured gate ready to be used as an axum layer.
///
/// This struct is created by `Gate::cookie()` and can be customized
/// with `with_policy()` and `with_cookie_template()` before being applied
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
    /// # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
    /// # use axum_gate::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::Gate;
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie("my-app", jwt_codec)
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
    /// # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
    /// # use axum_gate::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::Gate;
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(AccessPolicy::<Role, Group>::deny_all());
    /// ```
    pub fn with_cookie_template(mut self, template: CookieBuilder<'static>) -> Self {
        self.cookie_template = template;
        self
    }

    /// Convenience: configure the secure cookie template via a closure using the high-level `CookieTemplateBuilder`.
    /// Starts from [`CookieTemplateBuilder::recommended()`] each time.
    /// Invalid configurations (e.g. SameSite=None without Secure) will panic to surface misconfiguration early.
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::auth::{AccessPolicy, Role, Group, Account};
    /// # use axum_gate::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::Gate;
    /// # use std::sync::Arc;
    /// # let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .with_policy(AccessPolicy::<Role, Group>::deny_all())
    ///     .configure_cookie_template(|tpl| {
    ///         tpl.name("auth-token")
    ///            .persistent(cookie::time::Duration::hours(12))
    ///     });
    /// ```
    pub fn configure_cookie_template<F>(mut self, f: F) -> Self
    where
        F: FnOnce(CookieTemplateBuilder) -> CookieTemplateBuilder,
    {
        let template = f(CookieTemplateBuilder::recommended());
        self.cookie_template = template.validate_and_build();
        self
    }

    /// Enables Prometheus metrics for audit logging.
    ///
    /// This is a no-op unless the `prometheus` feature is enabled. It is safe to call
    /// multiple times; metrics will only be registered once.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_metrics(self) -> Self {
        // Attempt to install metrics into the default registry; ignore errors to keep builder infallible.
        let _ = crate::infrastructure::audit::prometheus_metrics::install_prometheus_metrics();
        self
    }

    /// Installs Prometheus metrics for audit logging into the provided registry.
    ///
    /// Safe to call multiple times; metrics are only registered once.
    #[cfg(feature = "prometheus")]
    pub fn with_prometheus_registry(self, registry: &prometheus::Registry) -> Self {
        let _ = crate::infrastructure::audit::prometheus_metrics::install_prometheus_metrics_with_registry(registry);
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

impl<C> CookieGate<C, crate::auth::Role, crate::auth::Group>
where
    C: Codec,
{
    /// Convenience method to configure this gate to allow any logged-in user.
    ///
    /// This sets the access policy to allow any user with a valid authentication token,
    /// regardless of their specific role or group membership. It uses the role hierarchy
    /// to grant access to the lowest role (User) and all supervisor roles, effectively
    /// allowing any authenticated user.
    ///
    /// This method is only available for gates using the default Role and Group types.
    ///
    /// # Example
    /// ```rust
    /// # use axum_gate::auth::{Role, Group, Account};
    /// # use axum_gate::jwt::{JsonWebToken, JwtClaims};
    /// # use axum_gate::prelude::Gate;
    /// # use std::sync::Arc;
    /// let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
    ///
    /// // This allows any authenticated user (User, Reporter, Moderator, Admin roles)
    /// let gate = Gate::cookie("my-app", jwt_codec)
    ///     .require_login()
    ///     .configure_cookie_template(|tpl| tpl.name("auth-token"));
    /// ```
    pub fn require_login(mut self) -> Self {
        use crate::auth::Role;
        self.policy = AccessPolicy::require_role_or_supervisor(Role::User);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Account, Group, Role};

    use crate::http::cookie::CookieBuilder;
    use crate::jwt::{JsonWebToken, JwtClaims};
    use std::sync::Arc;

    #[test]
    fn cookie_creates_gate_with_deny_all_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec);

        assert_eq!(gate.issuer, "test-app");
        assert!(gate.policy.denies_all());
    }

    #[test]
    fn require_login_creates_gate_with_user_or_supervisor_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec).require_login();

        assert_eq!(gate.issuer, "test-app");
        assert!(!gate.policy.denies_all());
        assert!(gate.policy.has_requirements());

        // Should have one role requirement for User with supervisor access
        let role_requirements = gate.policy.role_requirements();
        assert_eq!(role_requirements.len(), 1);
        assert_eq!(role_requirements[0].role, Role::User);
        assert!(role_requirements[0].allow_supervisor_access);

        // Should not have any group or permission requirements
        assert!(gate.policy.group_requirements().is_empty());
        assert!(gate.policy.permission_requirements().is_empty());
    }

    #[test]
    fn with_policy_updates_access_policy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let custom_policy: AccessPolicy<Role, Group> = AccessPolicy::require_role(Role::Admin);

        let gate: CookieGate<_, Role, Group> =
            Gate::cookie("test-app", jwt_codec).with_policy(custom_policy);

        assert!(!gate.policy.denies_all());
        let role_requirements = gate.policy.role_requirements();
        assert_eq!(role_requirements.len(), 1);
        assert_eq!(role_requirements[0].role, Role::Admin);
        assert!(!role_requirements[0].allow_supervisor_access);
    }

    #[test]
    fn with_cookie_template_updates_cookie_configuration() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let custom_template = CookieBuilder::new("custom-cookie", "");

        let _gate: CookieGate<_, Role, Group> =
            Gate::cookie("test-app", jwt_codec).with_cookie_template(custom_template);

        // Note: CookieBuilder doesn't have a public name() method, so we can't directly test this
        // The test verifies the method compiles and runs without error
    }

    #[test]
    fn configure_cookie_template_uses_closure() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());

        let _gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec)
            .configure_cookie_template(|tpl| {
                tpl.name("configured-cookie")
                    .persistent(cookie::time::Duration::hours(2))
            });

        // Note: CookieBuilder doesn't have a public name() method, so we can't directly test this
        // The test verifies the method compiles and runs without error
    }

    #[test]
    fn require_login_allows_all_role_hierarchy() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec).require_login();

        // The policy should allow User role with supervisor access, which means
        // it should allow User, Reporter, Moderator, and Admin roles
        let (role_requirements, _, _) = gate.policy.into_components();
        assert_eq!(role_requirements.len(), 1);

        let requirement = &role_requirements[0];
        assert_eq!(requirement.role, Role::User);
        assert!(requirement.allow_supervisor_access);

        // This effectively allows all roles in the hierarchy since User is the lowest
        // and allow_supervisor_access is true
    }

    #[test]
    fn require_login_can_be_chained_with_other_methods() {
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let gate: CookieGate<_, Role, Group> = Gate::cookie("test-app", jwt_codec)
            .require_login()
            .configure_cookie_template(|tpl| tpl.name("custom-auth"));

        // Note: CookieBuilder doesn't have a public name() method, so we can't directly test this
        // The test verifies the method compiles and runs without error
        assert!(!gate.policy.denies_all());
        assert!(gate.policy.has_requirements());
    }
}
