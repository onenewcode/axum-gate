#![allow(clippy::module_name_repetitions)]
//! Opinionated secure cookie template builder used by `Gate`.
//!
//! This builder provides a high–level, ergonomic API for defining the
//! authentication cookie issued and validated by the gate / login handlers.
//!
//! # Goals
//! * Secure by default (strictest sensible defaults)
//! * Explicit opt‑out for weaker settings
//! * Clear, discoverable configuration methods
//! * Simple conversion into the underlying `cookie::CookieBuilder`
//!
//! # Defaults
//! The `Default` implementation (and [`CookieTemplateBuilder::recommended`]) produce a *session* cookie
//! (no persistent `Max-Age`) whose exact security posture depends on build mode:
//!
//! Release (production):
//! * name: `axum-gate`
//! * value: empty string (value is set when issuing a token)
//! * path: `/`
//! * domain: unset
//! * `Secure`: true
//! * `HttpOnly`: true
//! * `SameSite`: `Strict`
//! * `Max-Age`: unset (session cookie – reduces risk if browser left open)
//!
//! Debug (development ergonomics):
//! * name: `axum-gate`
//! * value: empty string
//! * path: `/`
//! * domain: unset
//! * `Secure`: false (allows http:// localhost during development)
//! * `HttpOnly`: true
//! * `SameSite`: `Lax` (still CSRF-resistant for normal POSTs while easing some local redirect flows)
//! * `Max-Age`: unset
//!
//! You must explicitly opt-in to weaker settings in production builds; the release
//! defaults remain maximally strict.
//!
//! These defaults enforce maximal security and CSRF / XSS resistance.
//! You must *deliberately* loosen anything (e.g. switch to `Lax`, disable
//! `Secure` for local HTTP dev, or set a persistent lifetime).
//!
//! # Usage
//!
//! ```rust
//! use axum_gate::http::{cookie, SameSite, Duration};
//! use axum_gate::infrastructure::web::cookie_template::CookieTemplateBuilder;
//!
//! // Start from the secure defaults and only relax what you *really* need.
//! let template = CookieTemplateBuilder::recommended()
//!     .name("auth-token")                 // custom name
//!     .persistent(Duration::hours(24))    // explicitly make it persistent
//!     .same_site(SameSite::Lax);          // relax CSRF policy (e.g. for OAuth flows)
//!
//! // Convert to the underlying CookieBuilder when configuring the Gate:
//! let cookie_builder = template.build();
//! // gate.with_cookie_template(cookie_builder);
//! ```
//!
//! For local (non‑HTTPS) development you may disable `Secure` BUT do so explicitly:
//!
//! ```rust
//! # use axum_gate::infrastructure::web::cookie_template::CookieTemplateBuilder;
//! let insecure_dev_template = CookieTemplateBuilder::recommended()
//!     .insecure_dev_only(); // panic in release if used
//! ```
//!
//! # Extensibility
//!
//! If additional attributes are needed later (e.g. `SameSite=None` + `__Host-`
//! prefix validations, partitioned cookies once stabilized, etc.) add further
//! builder methods without breaking ergonomics.
//!
//! # Rationale
//! A bespoke builder:
//! * documents the security stance explicitly
//! * reduces repetition of secure flags at every call site
//! * keeps the public `Gate` API concise
//!
//! The crate has not been published yet, so we are free to introduce this helper
//! without backwards compatibility concerns.

use std::borrow::Cow;

use cookie::time::Duration;
use cookie::{CookieBuilder, SameSite};

/// Default cookie name used by the gate when none is specified.
pub const DEFAULT_COOKIE_NAME: &str = "axum-gate";

/// High‑level secure template for authentication cookies.
///
/// Convert into the underlying `CookieBuilder` via [`CookieTemplateBuilder::build`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieTemplateBuilder {
    name: Cow<'static, str>,
    value: Cow<'static, str>,
    path: Cow<'static, str>,
    domain: Option<Cow<'static, str>>,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    max_age: Option<Duration>,
}

impl Default for CookieTemplateBuilder {
    fn default() -> Self {
        // In debug (development) builds we relax a couple of flags to improve local ergonomics
        // (allow http and slightly looser cross-site navigation) while still keeping HttpOnly
        // and a session-only lifetime. In release we enforce the strict, secure posture.
        let (secure, same_site) = if cfg!(debug_assertions) {
            (false, SameSite::Lax)
        } else {
            (true, SameSite::Strict)
        };

        Self {
            name: Cow::Borrowed(DEFAULT_COOKIE_NAME),
            value: Cow::Borrowed(""),
            path: Cow::Borrowed("/"),
            domain: None,
            secure,
            http_only: true,
            same_site,
            max_age: None, // session cookie – safer by default
        }
    }
}

impl CookieTemplateBuilder {
    /// Secure recommended defaults (alias of `Default::default()`).
    #[must_use]
    pub fn recommended() -> Self {
        Self::default()
    }

    /// Set / override the cookie name.
    ///
    /// Keep names short and avoid sensitive info.
    #[must_use]
    pub fn name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.name = name.into();
        self
    }

    /// Provide an initial value (normally left empty – the login code will
    /// insert the JWT).
    #[must_use]
    pub fn value(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.value = value.into();
        self
    }

    /// Set the cookie path (default `/`).
    #[must_use]
    pub fn path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the cookie domain. Avoid setting for single‑domain apps
    /// to retain host-only semantics (slightly tighter).
    #[must_use]
    pub fn domain(mut self, domain: impl Into<Cow<'static, str>>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Unset the previously configured domain (host-only cookie).
    #[must_use]
    pub fn clear_domain(mut self) -> Self {
        self.domain = None;
        self
    }

    /// Explicitly mark the cookie as secure (HTTPS only).
    #[must_use]
    pub fn secure(mut self, flag: bool) -> Self {
        self.secure = flag;
        self
    }

    /// Convenience: DISABLE secure flag for local dev ONLY.
    ///
    /// In `release` builds this will panic to prevent accidental insecure
    /// deployment. You must call this intentionally; no environment detection
    /// is performed here.
    #[must_use]
    pub fn insecure_dev_only(mut self) -> Self {
        #[cfg(not(debug_assertions))]
        panic!("insecure_dev_only() must not be used in release builds");
        self.secure = false;
        self
    }

    /// Set / unset HttpOnly flag.
    #[must_use]
    pub fn http_only(mut self, flag: bool) -> Self {
        self.http_only = flag;
        self
    }

    /// Set the SameSite attribute (default `Strict`).
    ///
    /// Consider `Lax` for some OAuth / cross-site redirect flows. Only use
    /// `None` when you understand the CSRF implications and the need for
    /// `Secure`.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Make persistent with a specific `Max-Age`.
    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Remove persistence (session cookie again).
    #[must_use]
    pub fn clear_max_age(mut self) -> Self {
        self.max_age = None;
        self
    }

    /// Convenience for setting a persistent cookie lifetime.
    #[must_use]
    pub fn persistent(self, duration: Duration) -> Self {
        self.max_age(duration)
    }

    /// Use a short-lived cookie (e.g. 15 minutes) – explicit for readability.
    #[must_use]
    pub fn short_lived(self) -> Self {
        self.max_age(Duration::minutes(15))
    }

    /// Convert into the underlying `cookie::CookieBuilder<'static>` so the
    /// existing `Gate` API can accept it seamlessly.
    #[must_use]
    pub fn build(&self) -> CookieBuilder<'static> {
        let mut builder = CookieBuilder::new(self.name.clone(), self.value.clone())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(self.same_site)
            .path(self.path.clone());

        if let Some(ref domain) = self.domain {
            builder = builder.domain(domain.clone());
        }

        if let Some(max_age) = self.max_age {
            builder = builder.max_age(max_age);
        }

        builder
    }
}

/// (Optional) Validate invariants before building.
/// Currently trivial; reserved for future checks (e.g. enforcing `Secure` when
/// `SameSite=None`).
impl CookieTemplateBuilder {
    /// Validate the template configuration. Returns `Ok(())` if fine.
    pub fn validate(&self) -> Result<(), CookieTemplateBuilderError> {
        if self.same_site == SameSite::None && !self.secure {
            return Err(CookieTemplateBuilderError::InsecureNoneSameSite);
        }
        Ok(())
    }

    /// Validate then build. Panics if invalid (ergonomic for tests / examples / examples).
    #[must_use]
    pub fn validate_and_build(&self) -> CookieBuilder<'static> {
        self.validate()
            .expect("invalid CookieTemplateBuilder configuration");
        self.build()
    }
}

/// Possible configuration issues detected during validation.
#[derive(Debug, thiserror::Error)]
pub enum CookieTemplateBuilderError {
    #[error("SameSite=None requires Secure=true (browser enforcement & CSRF protection)")]
    InsecureNoneSameSite,
}
