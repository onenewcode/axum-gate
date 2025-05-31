//! Route handler for [axum].
use crate::codecs::CodecService;
use crate::cookie::CookieBuilder;
use crate::credentials::{Credentials, CredentialsVerifierService};
use crate::jwt::{JwtClaims, RegisteredClaims};
use crate::passport::Passport;
use crate::storage::PassportStorageService;
use axum::Json;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use std::fmt::Display;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Can be used to log a user in.
pub async fn login<CredVeri, PpStore, Pp, Codec>(
    cookie_jar: CookieJar,
    request_credentials: Json<Credentials<Pp::Id>>,
    registered_claims: RegisteredClaims,
    credentials_verifier: Arc<CredVeri>,
    passport_storage: Arc<PpStore>,
    codec: Arc<Codec>,
    cookie_template: CookieBuilder<'static>,
) -> Result<CookieJar, StatusCode>
where
    Pp::Id: Into<Vec<u8>> + Clone + Display + std::fmt::Debug,
    CredVeri: CredentialsVerifierService<Pp::Id>,
    PpStore: PassportStorageService<Pp>,
    Pp: Passport + Clone,
    Codec: CodecService<Payload = JwtClaims<Pp>>,
{
    let creds = request_credentials.0;
    let creds_to_verify = Credentials::new(creds.id.clone(), &creds.secret);
    match credentials_verifier
        .verify_credentials(&creds_to_verify)
        .await
    {
        Ok(true) => (),
        Ok(false) => {
            debug!("Hashed creds do not match.");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let passport = match passport_storage.passport(&creds.id).await {
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(Some(p)) => p,
        Ok(_) => {
            warn!(
                "Inconsistencies between credentials verifier service and passport storage state. The user with ID: {} verified its credentials but no passport available. Could not login.",
                creds.id
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let claims = JwtClaims::new(passport, registered_claims);
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
