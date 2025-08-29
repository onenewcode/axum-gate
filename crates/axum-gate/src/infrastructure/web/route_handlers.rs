//! Pre-defined route handlers for authentication operations.
//!
//! This module provides ready-to-use handlers for common authentication workflows
//! like user login and logout. These handlers integrate seamlessly with your
//! chosen storage implementations and JWT configuration.
//!
//! # Login Handler
//!
//! The `login` handler authenticates user credentials and sets a JWT cookie:
//!
//! ```rust
//! use axum::{routing::post, Router, Json};
//! use axum_gate::{
//!     route_handlers::login, Credentials, RegisteredClaims, CookieJar,
//!     memory::{MemorySecretRepository, MemoryAccountRepository},
//!     JsonWebToken, JwtClaims, Account, Role, Group
//! };
//! use std::sync::Arc;
//!
//! async fn login_endpoint(
//!     cookie_jar: CookieJar,
//!     Json(credentials): Json<Credentials<String>>,
//!     // Your repositories and codec would be provided via extensions or state
//! ) -> Result<CookieJar, axum::http::StatusCode> {
//!     let registered_claims = RegisteredClaims::new("my-app",
//!         chrono::Utc::now().timestamp() as u64 + 3600); // 1 hour expiry
//!
//!     let secret_verifier = Arc::new(MemorySecretRepository::default());
//!     let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//!     let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
//!     let cookie_template = cookie::CookieBuilder::new("auth-token", "")
//!         .secure(true)
//!         .http_only(true);
//!
//!     login(
//!         cookie_jar,
//!         credentials,
//!         registered_claims,
//!         secret_verifier,
//!         account_repo,
//!         jwt_codec,
//!         cookie_template,
//!     ).await
//! }
//! ```
//!
//! # Logout Handler
//!
//! The `logout` handler removes the authentication cookie:
//!
//! ```rust
//! use axum_gate::{route_handlers::logout, CookieJar};
//!
//! async fn logout_endpoint(cookie_jar: CookieJar) -> CookieJar {
//!     let cookie_template = cookie::CookieBuilder::new("auth-token", "");
//!     logout(cookie_jar, cookie_template).await
//! }
//! ```
//!
//! # Permission Management Functions
//!
//! This module also provides utility functions for managing user permissions
//! using the zero-synchronization permission system:
//!
//! ```rust
//! use axum_gate::route_handlers::{grant_user_permissions, check_user_permissions};
//! use axum_gate::Permissions;
//!
//! let mut user_permissions = Permissions::new();
//! let permissions_to_grant = vec!["read:file".to_string(), "write:file".to_string()];
//!
//! // Grant permissions
//! grant_user_permissions(&mut user_permissions, &permissions_to_grant);
//!
//! // Check permissions
//! let required_permissions = vec!["read:file".to_string()];
//! if check_user_permissions(&user_permissions, &required_permissions) {
//!     println!("User has required permissions");
//! }
//! ```
use crate::application::auth::{LoginResult, LoginService, LogoutService};
use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::AccessHierarchy;
use crate::http::cookie::CookieBuilder;
use crate::infrastructure::jwt::{JwtClaims, RegisteredClaims};
use crate::ports::Codec;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::AccountRepository;

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
            Ok(cookie_jar.add(cookie))
        }
        LoginResult::InvalidCredentials => Err(StatusCode::UNAUTHORIZED),
        LoginResult::InternalError(msg) => {
            error!("Login internal error: {}", msg);
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
/// use axum_gate::{route_handlers::logout, CookieJar};
///
/// async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
///     let cookie_template = cookie::CookieBuilder::new("auth-token", "");
///     logout(cookie_jar, cookie_template).await
/// }
/// ```
pub async fn logout(cookie_jar: CookieJar, cookie_template: CookieBuilder<'static>) -> CookieJar {
    let logout_service = LogoutService::new();
    logout_service.logout();

    let cookie = cookie_template.build();
    cookie_jar.remove(cookie)
}
