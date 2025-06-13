//! Implementation for [axum]
use self::access_scope::AccessScope;
use self::state::GateState;
use crate::Account;
use crate::jwt::JwtClaims;
use crate::services::CodecService;
use crate::utils::AccessHierarchy;

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::{DateTime, Utc};
use cookie::CookieBuilder;
use http::StatusCode;
use tower::{Layer, Service};
use tracing::{debug, trace, warn};

mod access_scope;
mod state;

/// The gate is protecting your application from unauthorized access.
#[derive(Clone)]
pub struct Gate<Codec, R, G>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    issuer: String,
    role_scopes: Vec<AccessScope<R>>,
    group_scope: Vec<G>,
    codec: Arc<Codec>,
    cookie_template: CookieBuilder<'static>,
    state: Arc<GateState>,
}

impl<Codec, R, G> Gate<Codec, R, G>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new instance of a gate.
    pub fn new(issuer: &str, codec: Arc<Codec>) -> Self {
        Self {
            issuer: issuer.to_string(),
            role_scopes: vec![],
            group_scope: vec![],
            codec,
            cookie_template: CookieBuilder::new("axum-gate", ""),
            state: Arc::new(GateState::new(Utc::now())),
        }
    }

    /// Adds the cookie builder as a template for the cookie used for auth.
    pub fn with_cookie_template(mut self, template: CookieBuilder<'static>) -> Self {
        self.cookie_template = template;
        self
    }

    /// Users with the given role are granted access.
    pub fn grant_role(mut self, role: R) -> Self {
        self.role_scopes.push(AccessScope::new(role));
        self
    }

    /// Users with the given role and all [supervisor](AccessHierarchy::supervisor)
    /// roles are granted access.
    pub fn grant_role_and_supervisor(mut self, role: R) -> Self {
        self.role_scopes
            .push(AccessScope::new(role).allow_supervisor());
        self
    }

    /// Users that are member of the given groupe are granted access.
    pub fn grant_group(mut self, group: G) -> Self {
        self.group_scope.push(group);
        self
    }
}

impl<Codec, R, G, S> Layer<S> for Gate<Codec, R, G>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    type Service = GateService<Codec, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            issuer: self.issuer.clone(),
            role_scopes: self.role_scopes.clone(),
            group_scope: self.group_scope.clone(),
            codec: Arc::clone(&self.codec),
            cookie_template: self.cookie_template.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

/// The gate is protecting your application from unauthorized access.
#[derive(Debug, Clone)]
pub struct GateService<Codec, R, G, S>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    inner: S,
    issuer: String,
    role_scopes: Vec<AccessScope<R>>,
    group_scope: Vec<G>,
    codec: Arc<Codec>,
    cookie_template: CookieBuilder<'static>,
    state: Arc<GateState>,
}

impl<Codec, R, G, S> GateService<Codec, R, G, S>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new instance of a gate.
    pub fn new(
        inner: S,
        issuer: &str,
        codec: Arc<Codec>,
        cookie_template: CookieBuilder<'static>,
        state: Arc<GateState>,
    ) -> Self {
        Self {
            inner,
            issuer: issuer.to_string(),
            role_scopes: vec![],
            group_scope: vec![],
            codec,
            cookie_template,
            state,
        }
    }

    fn authorized_by_role(&self, account: &Account<R, G>) -> bool {
        account
            .roles
            .iter()
            .any(|r| self.role_scopes.iter().any(|scope| scope.grants_role(r)))
    }

    fn authorized_by_minimum_role(&self, account: &Account<R, G>) -> bool {
        debug!("Checking if any subordinate role matches the required one.");
        account.roles.iter().any(|ur| {
            self.role_scopes
                .iter()
                .any(|scope| scope.grants_supervisor(ur))
        })
    }

    fn authorized_by_group(&self, account: &Account<R, G>) -> bool {
        account
            .groups
            .iter()
            .any(|r| self.group_scope.iter().any(|g_scope| g_scope.eq(r)))
    }
}

impl<Codec, R, G, S> GateService<Codec, R, G, S>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Queries the axum-gate auth cookie from the request.
    pub fn auth_cookie(&self, req: &Request<Body>) -> Option<Cookie> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        let cookie = self.cookie_template.clone().build();
        cookie_jar.get(cookie.name()).cloned()
    }

    /// Used to return the unauthorized response.
    fn unauthorized() -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Unauthorized"))
            .unwrap()
    }
}

impl<Codec, R, G, S> Service<Request<Body>> for GateService<Codec, R, G, S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    Account<R, G>: Clone,
    Codec: CodecService<Payload = JwtClaims<Account<R, G>>>,
    R: AccessHierarchy + Eq + std::fmt::Display + Sync + Send + 'static,
    G: Eq + Sync + Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let unauthorized_future = Box::pin(async move { Ok(Self::unauthorized()) });

        if self.group_scope.is_empty() && self.role_scopes.is_empty() {
            debug!("Denying access because roles and groups are empty.");
            return unauthorized_future;
        }

        let Some(auth_cookie) = self.auth_cookie(&req) else {
            return unauthorized_future;
        };
        trace!("axum-gate cookie: {auth_cookie:#?}");
        let cookie_value = auth_cookie.value_trimmed();
        let jwt = match self.codec.decode(cookie_value.as_bytes()) {
            Err(e) => {
                debug!("Could not decode cookie value: {e}");
                return unauthorized_future;
            }
            Ok(j) => j,
        };
        debug!("Logged in with id: {}", jwt.custom_claims.account_id);

        if !jwt.has_issuer(&self.issuer) {
            warn!(
                "Access for issuer {:?} denied. User: {}",
                jwt.registered_claims.issuer, jwt.custom_claims.account_id
            );
            return unauthorized_future;
        }

        let account = &jwt.custom_claims;
        let is_authorized = if self.authorized_by_role(account)
            || self.authorized_by_minimum_role(account)
            || self.authorized_by_group(account)
        {
            req.extensions_mut().insert(jwt.custom_claims.clone());
            req.extensions_mut().insert(jwt.registered_claims.clone());
            true
        } else {
            false
        };

        if !is_authorized {
            return unauthorized_future;
        }

        let Some(issued_at_time) =
            DateTime::<Utc>::from_timestamp(jwt.registered_claims.issued_at_time as i64, 0)
        else {
            debug!("Invalid issued_at_time, could not convert it from_timestamp.");
            return unauthorized_future;
        };

        let req = req;
        let state = Arc::clone(&self.state);
        let inner = self.inner.call(req);
        Box::pin(async move {
            if state.needs_invalidation(issued_at_time).await {
                debug!(
                    "User {} has been logged out because of invalidation check.",
                    jwt.custom_claims.account_id
                );
                return Ok(Self::unauthorized());
            }

            if is_authorized {
                return inner.await;
            }
            Ok(Self::unauthorized())
        })
    }
}
