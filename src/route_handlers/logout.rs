use crate::authn::LogoutService;
use cookie::CookieBuilder;

use axum_extra::extract::CookieJar;

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
/// use axum_gate::route_handlers::logout;
/// use axum_extra::extract::CookieJar;
/// use cookie::CookieBuilder;
///
/// async fn logout_handler(cookie_jar: CookieJar) -> CookieJar {
///     let cookie_template = CookieBuilder::new("auth-token", "");
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
