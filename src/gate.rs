//! Implementation for [axum]
use crate::roles::RoleHierarchy;
use axum::{BoxError, body::Body, extract::Request, http::Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use http::StatusCode;
use pin_project::pin_project;
use std::{
    convert::Infallible,
    fmt::Display,
    future::{Future, Ready, ready},
    pin::Pin,
    task::Poll,
};
use tower::{Layer, Service, ServiceBuilder};
use tracing::{debug, error, trace};

/// The gate is protecting your application from unauthorized access.
#[derive(Clone)]
pub struct Gate<R>
where
    R: Default + RoleHierarchy,
{
    required_role: R,
    allow_supervisor_access: bool,
}

impl<R> Gate<R>
where
    R: Default + RoleHierarchy,
{
    /// Creates a new instance of a gate.
    pub fn new() -> Self {
        Self {
            required_role: R::default(),
            allow_supervisor_access: false,
        }
    }
    /// Configures the [Gate] so that only users that are logged in and have
    /// the given role are granted access.
    pub fn with_role(mut self, role: R) -> Self {
        self.required_role = role;
        self
    }

    /// Configures the [Gate] so that users that are logged in and have
    /// the given role, or all [supervisor](RoleHierarchy::supervisor)
    /// roles are granted access.
    pub fn with_minimum_role(mut self, role: R) -> Self {
        self.required_role = role;
        self.allow_supervisor_access = true;
        self
    }
}

impl<R, S> Layer<S> for Gate<R>
where
    R: Default + RoleHierarchy,
{
    type Service = GateService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            required_role: self.required_role,
            allow_supervisor_access: self.allow_supervisor_access,
        }
    }
}

/// The gate is protecting your application from unauthorized access.
#[derive(Debug, Clone)]
pub struct GateService<S, R>
where
    R: Default + RoleHierarchy,
{
    inner: S,
    required_role: R,
    allow_supervisor_access: bool,
}

impl<S, R> GateService<S, R>
where
    R: Default + RoleHierarchy,
{
    /// Creates a new instance of a gate.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            required_role: R::default(),
            allow_supervisor_access: false,
        }
    }
}

impl<S, R> GateService<S, R>
where
    R: Default + RoleHierarchy,
{
    /// Queries the cosmodrome auth cookie from the request.
    pub fn auth_cookie(&self, req: &Request<Body>) -> Option<Cookie> {
        let cookie_jar = CookieJar::from_headers(req.headers());
        cookie_jar.get("cosmodrome").cloned()
    }
}

impl<S, R> Service<Request<Body>> for GateService<S, R>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Error: Into<Infallible>,
    S::Future: Send + 'static,
    R: Default + RoleHierarchy,
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

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let Some(cosmo) = self.auth_cookie(&req) else {
            return AuthFuture::unauthorized();
        };
        trace!("Cosmodrome cookie: {cosmo:#?}");
        AuthFuture::authorized(self.inner.call(req))
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

/*
impl<S, R> Default for Gate<S, R>
where
    R: Default + RoleHierarchy,
{
    fn default() -> Self {
        Self {
            required_role: R::default(),
            allow_supervisor_access: false,
        }
    }
} */

/*
impl<R, S> Layer<S> for Gate<S, R>
where
    R: Default + RoleHierarchy,
{
    type Service = GateService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service { inner }
    }
}

/// Service implementation of a [Gate].
pub struct GateService<S> {
    inner: S,
}

impl<S> Service<Request> for GateService<S>
where
    S: Service<Request> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { Ok(inner.call(req).await?) })
    }
}
 */
