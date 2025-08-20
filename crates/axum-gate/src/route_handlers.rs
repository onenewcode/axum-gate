//! Pre-defined route handler for [axum] like `login` and `logout`.
#![doc = include_str!("../doc/route_handlers.md")]
use crate::cookie::CookieBuilder;
use crate::credentials::Credentials;
use crate::hashing::VerificationResult;
use crate::jwt::{JwtClaims, RegisteredClaims};
use crate::permissions::PermissionChecker;
use crate::services::{
    AccountStorageService, CodecService, CredentialsVerifierService, DynamicPermissionService,
};
use crate::utils::AccessHierarchy;
use crate::{Account, PermissionSet};

use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use tracing::{debug, error};
use uuid::Uuid;

/// Can be used to log a user in.
pub async fn login<CredVeri, AccStore, Codec, R, G>(
    cookie_jar: CookieJar,
    request_credentials: Json<Credentials<String>>,
    registered_claims: RegisteredClaims,
    secret_verifier: Arc<CredVeri>,
    account_storage: Arc<AccStore>,
    codec: Arc<Codec>,
    cookie_template: CookieBuilder<'static>,
) -> Result<CookieJar, StatusCode>
where
    R: AccessHierarchy + Eq,
    G: Eq,
    CredVeri: CredentialsVerifierService<Uuid>,
    AccStore: AccountStorageService<R, G>,
    Codec: CodecService<Payload = JwtClaims<Account<R, G>>>,
{
    let creds = request_credentials.0;

    let account = match account_storage.query_account_by_user_id(&creds.id).await {
        Ok(Some(acc)) => acc,
        Ok(_) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let creds_to_verify = Credentials::new(&account.account_id, &creds.secret);

    match secret_verifier.verify_credentials(creds_to_verify).await {
        Ok(VerificationResult::Ok) => (),
        Ok(VerificationResult::Unauthorized) => {
            debug!("Hashed creds do not match.");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let claims = JwtClaims::new(account, registered_claims);
    let jwt = match codec.encode(&claims) {
        Ok(jwt) => jwt,
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let json_string = match serde_json::to_string(&String::from_utf8(jwt).unwrap()) {
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(enc) => enc,
    };
    let mut cookie = cookie_template.build();
    cookie.set_value(json_string);
    Ok(cookie_jar.add(cookie))
}

/// Removes the cookie that authenticates a user.
pub async fn logout(cookie_jar: CookieJar, cookie_template: CookieBuilder<'static>) -> CookieJar {
    let cookie = cookie_template.build();
    cookie_jar.remove(cookie)
}

/// **DEPRECATED**: Uses `updated_permission_set` to update `permission_set`.
///
/// This handler is deprecated because the new zero-synchronization permission system
/// eliminates the need for dynamic permission set management. Permissions are now
/// automatically available when referenced by name using deterministic hashing.
///
/// ## Migration
///
/// Remove this endpoint from your routes. Instead of managing permission sets dynamically,
/// simply use permission names directly in your application:
///
/// ```rust
/// use axum_gate::permissions::PermissionChecker;
///
/// // Old way: Add permission to set, then grant to user
/// // permission_set.append_permission("read:new_feature").await?;
/// // user.grant_permission(permission_index);
///
/// // New way: Directly grant permission by name
/// // PermissionChecker::grant_permission(&mut user.permissions, "read:new_feature");
/// ```
#[deprecated(
    since = "0.5.0",
    note = "The new zero-sync permission system eliminates the need for dynamic permission set management"
)]
#[allow(deprecated)]
pub async fn extend_permission_set(
    updated_permission_set: Json<Vec<String>>,
    permission_set: Arc<PermissionSet>,
) -> StatusCode {
    if let Err(e) = permission_set
        .extend_permission_set(updated_permission_set.0)
        .await
    {
        error!("{e}");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

/// Grant permissions to a user by permission names.
///
/// This is the recommended way to manage user permissions in the new
/// zero-synchronization architecture. No permission set management required.
///
/// # Example Usage
///
/// ```
/// use axum_gate::PermissionChecker;
/// use roaring::RoaringBitmap;
///
/// let mut user_permissions = RoaringBitmap::new();
/// let permissions = vec!["read:file".to_string(), "write:file".to_string()];
///
/// for permission in &permissions {
///     PermissionChecker::grant_permission(&mut user_permissions, permission);
/// }
///
/// assert!(PermissionChecker::has_permission(&user_permissions, "read:file"));
/// ```
pub fn grant_user_permissions(
    user_permissions: &mut roaring::RoaringBitmap,
    permission_names: &[String],
) {
    for permission_name in permission_names {
        PermissionChecker::grant_permission(user_permissions, permission_name);
    }
}

/// Revoke permissions from a user by permission names.
pub fn revoke_user_permissions(
    user_permissions: &mut roaring::RoaringBitmap,
    permission_names: &[String],
) {
    for permission_name in permission_names {
        PermissionChecker::revoke_permission(user_permissions, permission_name);
    }
}

/// Check if a user has specific permissions.
pub fn check_user_permissions(
    user_permissions: &roaring::RoaringBitmap,
    required_permissions: &[String],
) -> bool {
    let permission_names: Vec<&str> = required_permissions.iter().map(|s| s.as_str()).collect();
    PermissionChecker::has_all_permissions(user_permissions, &permission_names)
}
