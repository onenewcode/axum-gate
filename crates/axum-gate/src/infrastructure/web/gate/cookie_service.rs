use crate::Account;
use crate::domain::services::authorization::AuthorizationService;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::AccessScope;
use crate::infrastructure::jwt::{JwtClaims, JwtValidationResult, JwtValidationService};
use crate::ports::Codec;

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use cookie::CookieBuilder;
use http::StatusCode;
use roaring::RoaringBitmap;
use tower::Service;
use tracing::{debug, trace, warn};

/// The gate is protecting your application from unauthorized access.
#[derive(Debug, Clone)]
pub struct CookieGateService<C, R, G, S>
where
    C: Codec,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    inner: S,
    authorization_service: AuthorizationService<R, G>,
    jwt_validation_service: JwtValidationService<C>,
    cookie_template: CookieBuilder<'static>,
}

impl<C, R, G, S> CookieGateService<C, R, G, S>
where
    C: Codec,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq,
{
    /// Creates a new instance of a cookie gate service.
    pub fn new(
        inner: S,
        issuer: &str,
        role_scopes: Vec<AccessScope<R>>,
        group_scope: Vec<G>,
        permissions: RoaringBitmap,
        codec: Arc<C>,
        cookie_template: CookieBuilder<'static>,
    ) -> Self {
        Self {
            inner,
            authorization_service: AuthorizationService::new(role_scopes, group_scope, permissions),
            jwt_validation_service: JwtValidationService::new(codec, issuer),
            cookie_template,
        }
    }
}

impl<C, R, G, S> CookieGateService<C, R, G, S>
where
    C: Codec,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Queries the axum-gate auth cookie from the request.
    pub fn auth_cookie(&self, req: &Request<Body>) -> Option<Cookie<'_>> {
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

impl<C, R, G, S> Service<Request<Body>> for CookieGateService<C, R, G, S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    Account<R, G>: Clone,
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
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

        if self.authorization_service.has_empty_criteria() {
            debug!("Denying access because roles, groups or permissions are empty.");
            return unauthorized_future;
        }

        let Some(auth_cookie) = self.auth_cookie(&req) else {
            return unauthorized_future;
        };
        trace!("axum-gate cookie: {auth_cookie:#?}");

        let cookie_value = auth_cookie.value_trimmed();
        let jwt = match self.jwt_validation_service.validate_token(cookie_value) {
            JwtValidationResult::Valid(jwt) => jwt,
            JwtValidationResult::InvalidToken => {
                debug!("JWT token validation failed");
                return unauthorized_future;
            }
            JwtValidationResult::InvalidIssuer { expected, actual } => {
                warn!(
                    "JWT issuer validation failed. Expected: '{}', Actual: '{}', Account: {}",
                    expected, actual, "unknown"
                );
                return unauthorized_future;
            }
        };

        debug!("Logged in with id: {}", jwt.custom_claims.account_id);

        let account = &jwt.custom_claims;
        let is_authorized = self.authorization_service.is_authorized(account);

        if !is_authorized {
            return unauthorized_future;
        }

        req.extensions_mut().insert(jwt.custom_claims.clone());
        req.extensions_mut().insert(jwt.registered_claims.clone());

        let inner = self.inner.call(req);
        Box::pin(async move { inner.await })
    }
}
