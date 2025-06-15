//! Implementation for [axum]
use self::access_scope::AccessScope;
use self::state::GateState;
use self::cookie_service::CookieGateService;
use crate::cookie::CookieBuilder;
use crate::services::CodecService;
use crate::utils::AccessHierarchy;

use std::sync::Arc;

use chrono::Utc;
use roaring::RoaringBitmap;
use tower::Layer;

mod access_scope;
mod state;
mod cookie_service;

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
    permissions: RoaringBitmap,
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
    /// Creates a new instance of a gate that uses JWT cookies, denying all requests by default.
    pub fn new_cookie(issuer: &str, codec: Arc<Codec>) -> Self {
        Self {
            issuer: issuer.to_string(),
            role_scopes: vec![],
            group_scope: vec![],
            permissions: RoaringBitmap::new(),
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

    /// Users that do have the given permission will be granted access.
    pub fn grant_permission<P: Into<u32>>(mut self, permission: P) -> Self {
        self.permissions.insert(permission.into());
        self
    }

    /// Users that do have the given permissions will be granted access.
    pub fn grant_permissions<P: Into<u32>>(mut self, permission: Vec<P>) -> Self {
        permission.into_iter().for_each(|p| {
            self.permissions.insert(p.into());
        });
        self
    }
}

impl<Codec, R, G, S> Layer<S> for Gate<Codec, R, G>
where
    Codec: CodecService,
    R: AccessHierarchy + Eq + std::fmt::Display,
    G: Eq + Clone,
{
    type Service = CookieGateService<Codec, R, G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service::new(
            inner,
            &self.issuer,
            self.role_scopes.clone(),
            self.group_scope.clone(),
            self.permissions.clone(),
            Arc::clone(&self.codec),
            self.cookie_template.clone(),
            Arc::clone(&self.state),
        )
    }
}
