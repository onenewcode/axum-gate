//! Implementation for [axum]
use crate::codecs::CodecService;
use crate::jwt::JwtClaims;
use crate::passport::Passport;
use crate::roles::AccessHierarchy;
use axum::{body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use http::StatusCode;
use pin_project::pin_project;
use std::convert::Infallible;
use std::fmt::Debug;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tower::{Layer, Service};
use tracing::{debug, error, trace};

/// Contains information about the granted access scope.
#[derive(Debug, Clone)]
struct AccessScope<Role>
where
    Role: Eq,
{
    /// The role attached to the scope.
    pub role: Role,
    /// Whether all supervisors are granted access.
    pub allow_supervisor_access: bool,
}

impl<Role> AccessScope<Role>
where
    Role: AccessHierarchy + Eq + Debug,
{
    /// Creates a new scope with the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            allow_supervisor_access: false,
        }
    }

    /// Returns `true` if the given role matches the scope.
    pub fn grants_role(&self, role: &Role) -> bool {
        self.role.eq(role)
    }

    /// Returns `true` if one of the supervisor of the given role is allowed to access.
    pub fn grants_supervisor(&self, role: &Role) -> bool {
        if !self.allow_supervisor_access {
            debug!("Scope {self:?} does not allow supervisor access.");
            return false;
        }
        debug!(
            "Checking user role {role:?} if it is a supervisor of the required role {:?}.",
            self.role
        );
        let mut subordinate_traveller_role = role.subordinate();
        while let Some(ref r) = subordinate_traveller_role {
            debug!("Logged in Role: {role:?}, Current subordinate to check: {r:?}");
            if self.grants_role(r) {
                return true;
            }
            subordinate_traveller_role = r.subordinate();
        }
        false
    }

    /// Allows access to all supervisor of the role of the scope.
    pub fn allow_supervisor(mut self) -> Self {
        self.allow_supervisor_access = true;
        self
    }
}

/// The gate is protecting your application from unauthorized access.
#[derive(Clone)]
pub struct Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
{
    role_scopes: Vec<AccessScope<Pp::Role>>,
    group_scope: Vec<Pp::Group>,
    codec: Arc<Codec>,
}

impl<Pp, Codec> Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
{
    /// Creates a new instance of a gate.
    pub fn new(codec: Arc<Codec>) -> Self {
        Self {
            role_scopes: vec![],
            group_scope: vec![],
            codec,
        }
    }
    /// Users with the given role are granted access.
    pub fn grant_role(mut self, role: Pp::Role) -> Self {
        self.role_scopes.push(AccessScope::new(role));
        self
    }

    /// Users with the given role and all [supervisor](AccessHierarchy::supervisor)
    /// roles are granted access.
    pub fn grant_role_and_supervisor(mut self, role: Pp::Role) -> Self {
        self.role_scopes
            .push(AccessScope::new(role).allow_supervisor());
        self
    }

    /// Users that are member of the given groupe are granted access.
    pub fn grant_group(mut self, group: Pp::Group) -> Self {
        self.group_scope.push(group);
        self
    }
}

impl<Pp, Codec, S> Layer<S> for Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
    Pp::Group: Clone,
{
    type Service = GateService<Pp, Codec, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            role_scopes: self.role_scopes.clone(),
            group_scope: self.group_scope.clone(),
            codec: Arc::clone(&self.codec),
        }
    }
}

/// The gate is protecting your application from unauthorized access.
#[derive(Debug, Clone)]
pub struct GateService<Pp, Codec, S>
where
    Codec: CodecService,
    Pp: Passport,
    Pp::Role: Debug,
{
    inner: S,
    role_scopes: Vec<AccessScope<Pp::Role>>,
    group_scope: Vec<Pp::Group>,
    codec: Arc<Codec>,
}

impl<Pp, Codec, S> GateService<Pp, Codec, S>
where
    Codec: CodecService,
    Pp: Passport,
    Pp::Role: Debug,
{
    /// Creates a new instance of a gate.
    pub fn new(inner: S, codec: Arc<Codec>) -> Self {
        Self {
            inner,
            role_scopes: vec![],
            group_scope: vec![],
            codec,
        }
    }

    fn authorized_by_role(&self, passport: &Pp) -> bool {
        passport
            .roles()
            .iter()
            .any(|r| self.role_scopes.iter().any(|scope| scope.grants_role(r)))
    }

    fn authorized_by_minimum_role(&self, passport: &Pp) -> bool {
        debug!("Checking if any subordinate role matches the required one.");
        passport.roles().iter().any(|ur| {
            self.role_scopes
                .iter()
                .any(|scope| scope.grants_supervisor(ur))
        })
    }

    fn authorized_by_group(&self, passport: &Pp) -> bool {
        passport
            .groups()
            .iter()
            .any(|r| self.group_scope.iter().any(|g_scope| g_scope.eq(r)))
    }
}

impl<Pp, Codec, S> GateService<Pp, Codec, S>
where
    Codec: CodecService,
    Pp: Passport,
{
    /// Queries the axum-gate auth cookie from the request.
    pub fn auth_cookie(&self, req: &Request<Body>) -> Option<Cookie> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        cookie_jar.get("axum-gate").cloned()
    }
}

impl<Pp, Codec, S> Service<Request<Body>> for GateService<Pp, Codec, S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Error: Into<Infallible>,
    S::Future: Send + 'static,
    Pp: Passport + Clone + Send + Sync + 'static,
    Codec: CodecService<Payload = JwtClaims<Pp>>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = AuthFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let Some(auth_cookie) = self.auth_cookie(&req) else {
            return AuthFuture::unauthorized();
        };
        trace!("axum-gate cookie: {auth_cookie:#?}");
        let cookie_value = auth_cookie.value_trimmed();
        let jwt = match self.codec.decode(cookie_value.as_bytes()) {
            Err(e) => {
                debug!("Could not decode cookie value: {e}");
                return AuthFuture::unauthorized();
            }
            Ok(j) => j,
        };
        debug!("Logged in with id: {}", jwt.custom_claims.id());

        let passport = &jwt.custom_claims;
        if self.authorized_by_role(passport)
            || self.authorized_by_minimum_role(passport)
            || self.authorized_by_group(passport)
        {
            req.extensions_mut().insert(jwt.custom_claims);
            req.extensions_mut().insert(jwt.registered_claims);
            return AuthFuture::authorized(self.inner.call(req));
        }
        AuthFuture::unauthorized()
    }
}

/// A future indicating whether the user is authorized to access.
#[pin_project]
pub struct AuthFuture<F> {
    #[pin]
    state: AuthFutureState<F>,
}

impl<F> AuthFuture<F> {
    /// Creates a new future that indicates unauthorized.
    pub fn unauthorized() -> Self {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("Unauthorized"))
            .unwrap();
        Self {
            state: AuthFutureState::Unauthorized(ready(Ok(response))),
        }
    }
    /// Creates a new future that indicates authorized.
    pub fn authorized(fut: F) -> Self {
        Self {
            state: AuthFutureState::Authorized(fut),
        }
    }
}

/// Possible states the future can become.
#[pin_project(project = AuthFutureStateProj)]
enum AuthFutureState<F> {
    /// The user is unauthorized.
    Unauthorized(#[pin] Ready<Result<Response<Body>, Infallible>>),
    /// The user is authorized, so the request is forwarded to the next inner
    /// service.
    Authorized(#[pin] F),
}

impl<F> Future for AuthFuture<F>
where
    F: Future<Output = Result<Response<Body>, Infallible>>,
{
    type Output = Result<Response<Body>, Infallible>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this.state.project() {
            AuthFutureStateProj::Unauthorized(fut) => fut.poll(cx),
            AuthFutureStateProj::Authorized(fut) => match fut.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(r)) => Poll::Ready(Ok(r)),
                Poll::Ready(Err(e)) => {
                    error!("{e}");
                    let resp = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Internal Server Error"))
                        .unwrap();
                    Poll::Ready(Ok(resp))
                }
            },
        }
    }
}
