//! Pre-defined route handler for [axum] like `login` and `logout`.
#![doc = include_str!("../doc/route_handlers.md")]
use crate::Account;
use crate::cookie::CookieBuilder;
use crate::credentials::Credentials;
use crate::hashing::VerificationResult;
use crate::jwt::{JwtClaims, RegisteredClaims};
use crate::services::{AccountStorageService, CodecService, CredentialsVerifierService};
use crate::utils::AccessHierarchy;
use axum::Json;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use std::sync::Arc;
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
