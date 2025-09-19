//! Audit logging utilities for sensitive operations.
//
//! This module is intentionally minimal and only defines functions when the
//! `audit-logging` feature is enabled. All call sites are also feature-gated,
//! so there is no need for separate enabled/disabled submodules or no-op
//! fallbacks here.
//
//! Security notes:
//! - Never log secrets, passwords, raw tokens, or JWT contents.
//! - Prefer stable identifiers (UUID/user_id), reason codes, and support codes.
//! - Keep spans/events coarse and avoid leaking internal state.
//
//! Enable via Cargo features (in the depending crate):
//! - `axum-gate = { version = "...", features = ["audit-logging"] }`
//
//! Environment and subscriber configuration are left to the application.

use tracing::{Level, Span, event, span};
use uuid::Uuid;

const TARGET: &str = "axum_gate::audit";

#[cfg(feature = "prometheus")]
use strum::AsRefStr;

#[cfg(feature = "prometheus")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
enum JwtInvalidKind {
    Issuer,
    Token,
}

#[cfg(feature = "prometheus")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
enum AccountDeleteOutcome {
    Start,
    Success,
    Failure,
}

#[cfg(feature = "prometheus")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
enum SecretRestored {
    True,
    False,
    #[strum(serialize = "none")]
    None_,
}

#[cfg(feature = "prometheus")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, AsRefStr)]
enum AccountInsertOutcome {
    Success,
    Failure,
}

/// Creates a request-scoped span with basic HTTP metadata.
///
/// Fields:
/// - method: HTTP method (e.g., GET)
/// - path: Request path (no query string)
/// - request_id: Optional stable identifier for correlation (header/correlation id)
pub fn request_span(method: &str, path: &str, request_id: Option<&str>) -> Span {
    match request_id {
        Some(id) => span!(target: TARGET, Level::INFO, "request", %method, %path, request_id = %id),
        None => span!(target: TARGET, Level::INFO, "request", %method, %path),
    }
}

/// Creates a span for authorization checks.
///
/// Fields:
/// - account_id: Optional internal stable identifier
/// - role: Optional active role label
pub fn authorization_span(account_id: Option<&Uuid>, role: Option<&str>) -> Span {
    match (account_id, role) {
        (Some(id), Some(role)) => {
            span!(target: TARGET, Level::INFO, "authz.check", account_id = %id, role = %role)
        }
        (Some(id), None) => span!(target: TARGET, Level::INFO, "authz.check", account_id = %id),
        (None, Some(role)) => span!(target: TARGET, Level::INFO, "authz.check", role = %role),
        (None, None) => span!(target: TARGET, Level::INFO, "authz.check"),
    }
}

/// Records an authorization success decision.
pub fn authorized(account_id: &Uuid, role: Option<&str>) {
    match role {
        Some(r) => {
            event!(target: TARGET, Level::INFO, account_id = %account_id, role = %r, "authorized")
        }
        None => event!(target: TARGET, Level::INFO, account_id = %account_id, "authorized"),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.authz_authorized.inc();
    }
}

/// Records an authorization denial decision with a coarse-grained reason code.
///
/// Avoid logging sensitive policy internals; prefer stable reason codes.
pub fn denied(account_id: Option<&Uuid>, reason_code: &str) {
    match account_id {
        Some(id) => {
            event!(target: TARGET, Level::WARN, account_id = %id, reason = %reason_code, "denied")
        }
        None => event!(target: TARGET, Level::WARN, reason = %reason_code, "denied"),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.authz_denied.with_label_values(&[reason_code]).inc();
    }
}

/// Records that a JWT had an invalid issuer.
pub fn jwt_invalid_issuer(expected: &str, actual: &str) {
    event!(
        target: TARGET,
        Level::WARN,
        expected_issuer = %expected,
        actual_issuer = %actual,
        "jwt_invalid_issuer"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.jwt_invalid
            .with_label_values(&[JwtInvalidKind::Issuer.as_ref()])
            .inc();
    }
}

/// Records that a JWT token was otherwise invalid (expired, signature, etc.).
pub fn jwt_invalid_token(summary: &str) {
    event!(target: TARGET, Level::WARN, error = %summary, "jwt_invalid_token");

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.jwt_invalid
            .with_label_values(&[JwtInvalidKind::Token.as_ref()])
            .inc();
    }
}

/// Records the start of an account deletion workflow.
pub fn account_delete_start(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_start"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.account_delete_outcome
            .with_label_values(&[
                AccountDeleteOutcome::Start.as_ref(),
                SecretRestored::None_.as_ref(),
            ])
            .inc();
    }
}

/// Records a successful account deletion.
pub fn account_delete_success(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_delete_success"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.account_delete_outcome
            .with_label_values(&[
                AccountDeleteOutcome::Success.as_ref(),
                SecretRestored::None_.as_ref(),
            ])
            .inc();
    }
}

/// Records an account deletion failure and the outcome of any compensating action.
pub fn account_delete_failure(
    user_id: &str,
    account_id: &Uuid,
    secret_restored: Option<bool>,
    error_summary: &str,
) {
    match secret_restored {
        Some(true) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = true,
            "account_delete_failure"
        ),
        Some(false) => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            secret_restored = false,
            "account_delete_failure"
        ),
        None => event!(
            target: TARGET,
            Level::ERROR,
            %user_id,
            account_id = %account_id,
            error = %error_summary,
            "account_delete_failure"
        ),
    }

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        let sr = match secret_restored {
            Some(true) => SecretRestored::True,
            Some(false) => SecretRestored::False,
            None => SecretRestored::None_,
        };
        m.account_delete_outcome
            .with_label_values(&[AccountDeleteOutcome::Failure.as_ref(), sr.as_ref()])
            .inc();
    }
}

/// Records a newly created account.
pub fn account_created(user_id: &str, account_id: &Uuid) {
    event!(
        target: TARGET,
        Level::INFO,
        %user_id,
        account_id = %account_id,
        "account_created"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.account_insert_outcome
            .with_label_values(&[AccountInsertOutcome::Success.as_ref(), "none"])
            .inc();
    }
}

/// Records an account insertion failure with a coarse-grained reason code.
///
/// The reason should be a low-cardinality, stable code (e.g., "duplicate_user_id",
/// "repo_error") to keep Prometheus label cardinality under control.
pub fn account_insert_failure(user_id: &str, reason_code: &str) {
    event!(
        target: TARGET,
        Level::ERROR,
        %user_id,
        reason = %reason_code,
        "account_insert_failure"
    );

    #[cfg(feature = "prometheus")]
    if let Some(m) = metrics() {
        m.account_insert_outcome
            .with_label_values(&[AccountInsertOutcome::Failure.as_ref(), reason_code])
            .inc();
    }
}
