use axum::extract::Json;
use axum::routing::{Router, get, post};
use axum_gate::claims::RegisteredClaims;
use axum_gate::codecs::JsonWebToken;
use axum_gate::credentials::{Credentials, HashedCredentials};
use axum_gate::hashing::Argon2Hasher;
use axum_gate::passport::BasicPassport;
use axum_gate::roles::BasicRole;
use axum_gate::storage::{CredentialsMemoryStorage, PassportMemoryStorage};
use std::sync::Arc;
use tracing_subscriber::prelude::*;

async fn index() -> Result<String, ()> {
    Ok("Hello axum!".to_string())
}

async fn admin() -> Result<String, ()> {
    Ok("Hello admin!".to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let creds = Credentials::new("admin@example.com", "admin_password");
    let hasher = Arc::new(Argon2Hasher::default());
    let hashed_creds =
        HashedCredentials::new_with_hasher(creds.id, creds.secret, &*hasher).unwrap();
    let creds_storage = Arc::new(CredentialsMemoryStorage::from(vec![hashed_creds.clone()]));

    let passport = BasicPassport::new(creds.id, &["admin"], &[BasicRole::Admin])
        .expect("Creating passport failed.");
    let passport_storage = Arc::new(PassportMemoryStorage::from(vec![passport]));
    let jwt_codec = Arc::new(JsonWebToken::default());

    let app = Router::new()
        .route("/admin", get(admin))
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::default();
                let credentials_verifier = Arc::clone(&creds_storage);
                let credentials_hasher = Arc::clone(&hasher);
                let passport_storage = Arc::clone(&passport_storage);
                let jwt_codec = Arc::clone(&jwt_codec);
                move |cookie_jar, request_credentials: Json<Credentials<String, String>>| {
                    axum_gate::route_handlers::login(
                        cookie_jar,
                        request_credentials,
                        registered_claims,
                        credentials_verifier,
                        credentials_hasher,
                        passport_storage,
                        jwt_codec,
                    )
                }
            }),
        )
        .route("/", get(index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
