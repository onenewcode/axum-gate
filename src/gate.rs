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
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::task::Poll;
use tower::{Layer, Service};
use tracing::{debug, error, trace};

/// The gate is protecting your application from unauthorized access.
#[derive(Clone)]
pub struct Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
{
    required_role: Pp::Role,
    allow_supervisor_access: bool,
    codec: Codec,
}

impl<Pp, Codec> Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
{
    /// Creates a new instance of a gate.
    pub fn new(codec: Codec) -> Self {
        Self {
            required_role: Pp::Role::default(),
            allow_supervisor_access: false,
            codec,
        }
    }
    /// Configures the [Gate] so that only users that are logged in and have
    /// the given role are granted access.
    pub fn with_role(mut self, role: Pp::Role) -> Self {
        self.required_role = role;
        self
    }

    /// Configures the [Gate] so that users that are logged in and have
    /// the given role, or all [supervisor](AccessHierarchy::supervisor)
    /// roles are granted access.
    pub fn with_minimum_role(mut self, role: Pp::Role) -> Self {
        self.required_role = role;
        self.allow_supervisor_access = true;
        self
    }
}

impl<Pp, Codec, S> Layer<S> for Gate<Pp, Codec>
where
    Codec: CodecService,
    Pp: Passport,
{
    type Service = GateService<Pp, Codec, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            required_role: self.required_role,
            allow_supervisor_access: self.allow_supervisor_access,
            codec: self.codec.clone(),
        }
    }
}

/// The gate is protecting your application from unauthorized access.
#[derive(Debug, Clone)]
pub struct GateService<Pp, Codec, S>
where
    Codec: CodecService,
    Pp: Passport,
{
    inner: S,
    required_role: Pp::Role,
    allow_supervisor_access: bool,
    codec: Codec,
}

impl<Pp, Codec, S> GateService<Pp, Codec, S>
where
    Codec: CodecService,
    Pp: Passport,
{
    /// Creates a new instance of a gate.
    pub fn new(inner: S, codec: Codec) -> Self {
        Self {
            inner,
            required_role: Pp::Role::default(),
            allow_supervisor_access: false,
            codec,
        }
    }

    fn authorized_by_role(&self, passport: &Pp) -> bool {
        if passport.roles().iter().any(|r| self.required_role.eq(r)) {
            debug!(
                "The logged in role matches directly with the required role. The user is always authorized for access. In this case."
            );
            return true;
        };

        if self.allow_supervisor_access {
            return self.authorized_by_minimum_role(passport);
        }
        false
    }

    fn authorized_by_minimum_role(&self, passport: &Pp) -> bool {
        debug!("Checking if any subordinate role matches the required one.");
        passport.roles().iter().any(|ur| {
            let mut subordinate_traveller_role = Some(*ur);
            debug!(
                "Checking user role {ur:?} if it is a supervisor of the required role {:?}.",
                self.required_role
            );
            while let Some(ref r) = subordinate_traveller_role {
                debug!("Logged in Role: {ur:?}, Current subordinate to check: {r:?}");
                if r.eq(&self.required_role) {
                    return true;
                }
                subordinate_traveller_role = r.subordinate();
            }
            false
        })
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

        if self.authorized_by_role(&jwt.custom_claims) {
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
