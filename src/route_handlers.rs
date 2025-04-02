//! Route handler for [axum].
use crate::claims::{JwtClaims, RegisteredClaims};
use crate::credentials::{Credentials, HashedCredentials};
use crate::passport::Passport;
use crate::services::{
    CodecService, CredentialsVerifierService, PassportStorageService, SecretsHashingService,
};
use axum::Json;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use std::fmt::Display;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// Can be used to log a user in.
pub async fn login<Secret, CredVeri, PpStore, Pp, Hasher, Codec>(
    cookie_jar: CookieJar,
    request_credentials: Json<Credentials<Pp::Id, Secret>>,
    registered_claims: RegisteredClaims,
    credentials_verifier: Arc<CredVeri>,
    credentials_hasher: Arc<Hasher>,
    passport_storage: Arc<PpStore>,
    codec: Arc<Codec>,
) -> Result<CookieJar, StatusCode>
where
    Pp::Id: Into<Vec<u8>> + Clone + Display + std::fmt::Debug,
    Secret: Into<Vec<u8>> + std::fmt::Debug,
    CredVeri: CredentialsVerifierService,
    PpStore: PassportStorageService<Pp>,
    Pp: Passport + Clone,
    Hasher: SecretsHashingService,
    Codec: CodecService<Payload = JwtClaims<Pp>>,
{
    let creds = request_credentials.0;
    debug!("{creds:#?}");
    let hashed_creds = match HashedCredentials::new_with_hasher(
        creds.id.clone(),
        creds.secret,
        &*credentials_hasher,
    ) {
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(c) => c,
    };
    match credentials_verifier.verify_credentials(&hashed_creds).await {
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

    let claims = JwtClaims::new_with_registered(passport, registered_claims);
    let jwt = match codec.encode(&claims) {
        Ok(jwt) => jwt,
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let json_string = match serde_json::to_string(&jwt) {
        Err(e) => {
            error!("{e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(enc) => enc,
    };
    let cookie = Cookie::new("axum-gate", json_string);
    Ok(cookie_jar.add(cookie))
}
