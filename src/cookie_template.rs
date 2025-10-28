//! Secure cookie template builder for authentication cookies.
//!
//! This module provides [`CookieTemplateBuilder`] for creating secure authentication
//! cookies with sensible defaults that automatically adjust based on build configuration.
//! The builder ensures proper security settings while maintaining development ergonomics.
//!
//! # Quick Start
//!
//! ```rust
//! use axum_gate::cookie_template::CookieTemplateBuilder;
//! use cookie::time::Duration;
//!
//! // Use secure defaults
//! let template = CookieTemplateBuilder::recommended()
//!     .name("auth-token")
//!     .persistent(Duration::hours(24))
//!     .build();
//! ```
//!
//! # Security Features
//!
//! The builder automatically provides secure defaults:
//! - **HttpOnly**: Prevents JavaScript access (XSS protection)
//! - **Secure**: HTTPS-only in production builds
//! - **SameSite=Strict**: CSRF protection in production
//! - **Session cookies**: No persistence by default
//! - **Development-friendly**: Relaxed settings in debug builds for localhost testing

#![allow(clippy::module_name_repetitions)]

use std::borrow::Cow;

use cookie::time::Duration;
use cookie::{CookieBuilder, SameSite};

/// Default cookie name used by the gate when none is specified.
pub const DEFAULT_COOKIE_NAME: &str = "axum-gate";

/// Builder for secure authentication cookies used by `Gate`.
///
/// Provides secure defaults that are automatically adjusted based on build configuration:
/// - **Production builds**: Secure=true, HttpOnly=true, SameSite=Strict, session cookie
/// - **Debug builds**: Secure=false (for localhost), SameSite=Lax, HttpOnly=true, session cookie
///
/// # Security Best Practices
///
/// The recommended approach is to start with [`CookieTemplateBuilder::recommended()`] and
/// customize only what you need:
///
/// ```rust
/// use axum_gate::cookie_template::CookieTemplateBuilder;
/// use cookie::{time::Duration, SameSite};
///
/// // Secure defaults with custom name and expiration
/// let template = CookieTemplateBuilder::recommended()
///     .name("auth-token")
///     .persistent(Duration::hours(24))
///     .build();
///
/// // For OAuth/redirect flows that need cross-site navigation
/// let oauth_template = CookieTemplateBuilder::recommended()
///     .name("oauth-state")
///     .same_site(SameSite::Lax)  // Allow cross-site for redirects
///     .build();
/// ```
///
/// # Security Features
///
/// - **HttpOnly**: Prevents JavaScript access to auth cookies (XSS protection)
/// - **Secure**: HTTPS-only in production (MITM protection)
/// - **SameSite=Strict**: Prevents CSRF attacks in production
/// - **Session cookies**: No persistent storage by default (privacy)
///
/// # Common Customizations
///
/// - `name("my-auth-cookie")` - Set custom cookie name
/// - `persistent(Duration::hours(24))` - Make cookie persist across browser sessions
/// - `same_site(SameSite::Lax)` - Allow cross-site navigation (OAuth flows)
/// - `domain(".example.com")` - Share cookies across subdomains
///
/// Convert to `cookie::CookieBuilder` via [`CookieTemplateBuilder::build`].
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
    /// Secure recommended defaults.
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

    /// Validate the template configuration. Returns `Ok(())` if fine.
    pub fn validate(&self) -> Result<(), CookieTemplateBuilderError> {
        if self.same_site == SameSite::None && !self.secure {
            return Err(CookieTemplateBuilderError::InsecureNoneSameSite);
        }
        Ok(())
    }

    /// Validate then build. Returns an error if invalid (`CookieTemplateBuilderError`).
    pub fn validate_and_build(&self) -> Result<CookieBuilder<'static>, CookieTemplateBuilderError> {
        self.validate()?;
        Ok(self.build())
    }
}

/// Possible configuration issues detected during validation.
#[derive(Debug, thiserror::Error)]
pub enum CookieTemplateBuilderError {
    #[error("SameSite=None requires Secure=true (browser enforcement & CSRF protection)")]
    /// SameSite=None requires Secure=true for browser security and CSRF protection.
    InsecureNoneSameSite,
}
