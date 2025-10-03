//! Pre-built route handlers for authentication workflows.
//!
//! This module provides ready-to-use handlers for common authentication operations:
//! [`login`] for user authentication and JWT cookie creation, and [`logout`] for
//! session termination. These handlers integrate with your storage backends and
//! JWT configuration to provide secure authentication endpoints.
//!
//! # Quick Setup
//!
//! ```rust
//! use axum::{routing::post, Router, Json, extract::State};
//! use axum_gate::route_handlers::{login, logout};
//! use axum_gate::prelude::Credentials;
//! use axum_gate::codecs::jwt::{RegisteredClaims, JsonWebToken, JwtClaims};
//! use axum_gate::accounts::Account;
//! use axum_gate::prelude::{Role, Group};
//! use axum_gate::repositories::memory::{MemorySecretRepository, MemoryAccountRepository};
//! use axum_extra::extract::CookieJar;
//! use std::sync::Arc;
//!
//! type AppJwtCodec = JsonWebToken<JwtClaims<Account<Role, Group>>>;
//!
//! #[derive(Clone)]
//! struct AppState {
//!     account_repo: Arc<MemoryAccountRepository<Role, Group>>,
//!     secret_repo: Arc<MemorySecretRepository>,
//!     jwt_codec: Arc<AppJwtCodec>,
//! }
//!
//! async fn login_handler(
//!     State(state): State<AppState>,
//!     cookie_jar: CookieJar,
//!     Json(credentials): Json<Credentials<String>>,
//! ) -> Result<CookieJar, axum::http::StatusCode> {
//!     let claims = RegisteredClaims::new("my-app",
//!         chrono::Utc::now().timestamp() as u64 + 3600); // 1 hour expiry
//!
//!     let cookie_template = cookie::CookieBuilder::new("auth-token", "")
//!         .secure(true)
//!         .http_only(true);
//!
//!     login(
//!         cookie_jar,
//!         credentials,
//!         claims,
//!         state.secret_repo,
//!         state.account_repo,
//!         state.jwt_codec,
//!         cookie_template,
//!     ).await
//! }
//!
//! async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
//!     let cookie_template = cookie::CookieBuilder::new("auth-token", "");
//!     logout(cookie_jar, cookie_template).await
//! }
//!
//! let app = Router::new()
//!     .route("/login", post(login_handler))
//!     .route("/logout", post(logout_handler))
//!     .with_state(app_state);
//! ```
//!
//! # Security Features
//!
//! The login handler includes built-in timing attack protection:
//! - Constant-time credential verification using the `subtle` crate
//! - Always performs password hashing, even for non-existent users
//! - Unified error responses prevent user enumeration attacks
//! - Applied consistently across all storage backend implementations
use crate::accounts::{Account, AccountRepository};
use crate::authn::{LoginResult, LoginService, LogoutService};
use crate::authz::AccessHierarchy;
use crate::codecs::Codec;
use crate::codecs::jwt::{JwtClaims, RegisteredClaims};
use crate::cookie::CookieBuilder;
use crate::credentials::Credentials;
use crate::credentials::CredentialsVerifier;

use std::sync::Arc;

use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use tracing::error;
use uuid::Uuid;

/// Authenticates user credentials and creates a JWT authentication cookie.
///
/// This handler validates the provided credentials against the secret repository,
/// retrieves the corresponding account from the account repository, and creates
/// a signed JWT cookie containing the user's authentication information.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar to add the auth cookie to
/// * `credentials` - User credentials for authentication
/// * `registered_claims` - JWT registered claims (issuer, expiration, etc.)
/// * `secret_verifier` - Repository for verifying user passwords
/// * `account_repository` - Repository for loading user account data
/// * `codec` - JWT codec for creating signed tokens
/// * `cookie_template` - Template for creating the authentication cookie
///
/// # Returns
/// * `Ok(CookieJar)` - Updated cookie jar with authentication cookie
/// * `Err(StatusCode)` - HTTP error code indicating failure reason
///   - `UNAUTHORIZED` - Invalid credentials (covers both non-existent users and wrong passwords)
///   - `INTERNAL_SERVER_ERROR` - System error during authentication
///
/// # Example Response Codes
/// - 200: Login successful, cookie set
/// - 401: Invalid username/password or account not found
/// - 500: Internal server error
pub async fn login<CredVeri, AccRepo, C, R, G>(
    cookie_jar: CookieJar,
    credentials: Credentials<String>,
    registered_claims: RegisteredClaims,
    secret_verifier: Arc<CredVeri>,
    account_repository: Arc<AccRepo>,
    codec: Arc<C>,
    cookie_template: CookieBuilder<'static>,
) -> Result<CookieJar, StatusCode>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
    CredVeri: CredentialsVerifier<Uuid>,
    AccRepo: AccountRepository<R, G>,
    C: Codec<Payload = JwtClaims<Account<R, G>>>,
{
    #[cfg(feature = "audit-logging")]
    let user_id = credentials.id.clone();
    #[cfg(feature = "audit-logging")]
    let _audit_span = tracing::span!(tracing::Level::INFO, "auth.login", user_id = %user_id);
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!(user_id = %user_id, "login_attempt");

    let login_service = LoginService::<R, G>::new();

    let result = login_service
        .authenticate(
            credentials,
            registered_claims,
            secret_verifier,
            account_repository,
            codec,
        )
        .await;

    match result {
        LoginResult::Success(jwt_string) => {
            let mut cookie = cookie_template.build();
            cookie.set_value(jwt_string);
            #[cfg(feature = "audit-logging")]
            tracing::info!(user_id = %user_id, "login_success");
            Ok(cookie_jar.add(cookie))
        }
        LoginResult::InvalidCredentials {
            user_message: _,
            support_code,
        } => {
            match support_code.as_deref() {
                Some(code) => {
                    error!(
                        "Login failed - Invalid credentials [Support Code: {}]",
                        code
                    );
                }
                None => {
                    error!("Login failed - Invalid credentials");
                }
            }
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::warn!(user_id = %user_id, support_code = %code, "login_failed_invalid_credentials")
                    }
                    None => {
                        tracing::warn!(user_id = %user_id, "login_failed_invalid_credentials")
                    }
                }
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        LoginResult::InternalError {
            user_message: _,
            technical_message,
            support_code,
            retryable,
        } => {
            let code_info = support_code
                .as_deref()
                .map(|c| format!(" [Support Code: {}]", c))
                .unwrap_or_default();
            let retry_info = if retryable {
                " [Retryable]"
            } else {
                " [Non-retryable]"
            };
            error!(
                "Login internal error{}{}: {}",
                code_info, retry_info, technical_message
            );
            #[cfg(feature = "audit-logging")]
            {
                match support_code.as_deref() {
                    Some(code) => {
                        tracing::error!(user_id = %user_id, support_code = %code, retryable = retryable, error = %technical_message, "login_internal_error")
                    }
                    None => {
                        tracing::error!(user_id = %user_id, retryable = retryable, error = %technical_message, "login_internal_error")
                    }
                }
            }
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Logs out a user by removing their authentication cookie.
///
/// This handler creates a cookie with the same name as the authentication cookie
/// but removes its value, effectively logging out the user. The browser will
/// delete the cookie when it receives this response.
///
/// # Arguments
/// * `cookie_jar` - The incoming cookie jar
/// * `cookie_template` - Template matching the authentication cookie to remove
///
/// # Returns
/// The updated cookie jar with the authentication cookie removed.
///
/// # Example
/// ```rust
/// use axum_gate::{auth::logout, http::CookieJar};
///
/// async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
///     let cookie_template = cookie::CookieBuilder::new("auth-token", "");
///     logout(cookie_jar, cookie_template).await
/// }
/// ```
pub async fn logout(cookie_jar: CookieJar, cookie_template: CookieBuilder<'static>) -> CookieJar {
    #[cfg(feature = "audit-logging")]
    let _audit_span = tracing::span!(tracing::Level::INFO, "auth.logout");
    #[cfg(feature = "audit-logging")]
    let _audit_enter = _audit_span.enter();
    #[cfg(feature = "audit-logging")]
    tracing::info!("logout");

    let logout_service = LogoutService::new();
    logout_service.logout();

    let cookie = cookie_template.build();
    cookie_jar.remove(cookie)
}
