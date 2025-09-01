#![allow(clippy::module_name_repetitions)]
//! Builder for the authentication cookie used by `Gate`.
//!
//! Defaults:
//! - Release: Secure=true, HttpOnly=true, SameSite=Strict, session cookie
//! - Debug:   Secure=false (localhost), SameSite=Lax, still HttpOnly & session
//!
//! Common overrides:
//! - name("auth-token")
//! - persistent(Duration::hours(24)) / max_age(...)
//! - same_site(SameSite::Lax) for OAuth-style redirects
//! - insecure_dev_only() for local HTTP only
//!
//! Example:
//! ```rust
//! use axum_gate::http::{Duration, SameSite};
//! use axum_gate::prelude::CookieTemplateBuilder;
//! let cookie_builder = CookieTemplateBuilder::recommended()
//!     .name("auth-token")
//!     .persistent(Duration::hours(12))
//!     .same_site(SameSite::Strict)
//!     .build();
//! ```
//!
//! All settings start secure; you must opt out explicitly.

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
