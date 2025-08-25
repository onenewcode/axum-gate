//! Implementation for [axum]
use self::cookie_service::CookieGateService;
use crate::cookie::CookieBuilder;
use crate::domain::services::access_policy::AccessPolicy;
use crate::domain::traits::AccessHierarchy;
use crate::ports::Codec;

use std::sync::Arc;

use tower::Layer;

mod cookie_service;

/// The gate is protecting your application from unauthorized access.
#[derive(Clone)]
pub struct Gate;

impl Gate {
    /// Creates a new cookie-based gate with the specified access policy.
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
    /// Use `with_policy()` to configure access requirements.
    pub fn cookie_deny_all<C, R, G>(issuer: &str, codec: Arc<C>) -> CookieGate<C, R, G>
    where
        C: Codec,
        R: AccessHierarchy + Eq + std::fmt::Display,
        G: Eq,
    {
        Self::cookie(issuer, codec, AccessPolicy::deny_all())
    }
}

/// The cookie gate uses JWT cookies for authorization.
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
    pub fn with_policy(mut self, policy: AccessPolicy<R, G>) -> Self {
        self.policy = policy;
        self
    }

    /// Configures the cookie template used for authentication.
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
