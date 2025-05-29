use axum::extract::Json;
use axum::routing::{Router, get, post};
use axum_gate::Account;
use axum_gate::cookie;
use axum_gate::credentials::Credentials;
use axum_gate::jsonwebtoken::DecodingKey;
use axum_gate::jsonwebtoken::EncodingKey;
use axum_gate::jsonwebtoken::Header;
use axum_gate::jsonwebtoken::Validation;
use axum_gate::jwt::{JsonWebToken, JsonWebTokenOptions, RegisteredClaims};
use axum_gate::roles::Role;
use axum_gate::storage::memory::{MemoryCredentialsStorage, MemoryPassportStorage};
use dotenv;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenv::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(JsonWebToken::new_with_options(JsonWebTokenOptions {
        enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(Header::default()),
        validation: Some(Validation::default()),
    }));

    let creds = Credentials::new("admin@example.com".to_string(), "admin_password");
    let reporter_creds = Credentials::new("reporter@example.com".to_string(), "reporter_password");
    let user_creds = Credentials::new("user@example.com".to_string(), "user_password");
    let creds_storage = Arc::new(
        MemoryCredentialsStorage::try_from(vec![
            creds.clone(),
            user_creds.clone(),
            reporter_creds.clone(),
        ])
        .unwrap(),
    );

    let admin_passport = Account::new(
        &creds.id.to_string(),
        &creds.id.to_string(),
        &["admin"],
        &[Role::Admin],
    )
    .expect("Creating passport failed.");
    let reporter_passport = Account::new(
        &reporter_creds.id.to_string(),
        &reporter_creds.id.to_string(),
        &["reporter"],
        &[Role::Reporter],
    )
    .expect("Creating passport failed.");
    let user_passport = Account::new(
        &user_creds.id.to_string(),
        &user_creds.id.to_string(),
        &["user"],
        &[Role::User],
    )
    .expect("Creating passport failed.");
    let passport_storage = Arc::new(MemoryPassportStorage::from(vec![
        admin_passport,
        user_passport,
        reporter_passport,
    ]));

    let cookie_template = cookie::CookieBuilder::new("axum-gate", "").secure(true);

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::default();
                let credentials_verifier = Arc::clone(&creds_storage);
                let passport_storage = Arc::clone(&passport_storage);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, request_credentials: Json<Credentials<String>>| {
                    axum_gate::route_handlers::login(
                        cookie_jar,
                        request_credentials,
                        registered_claims,
                        credentials_verifier,
                        passport_storage,
                        jwt_codec,
                        cookie_template,
                    )
                }
            }),
        )
        .route(
            "/logout",
            get({
                move |cookie_jar| axum_gate::route_handlers::logout(cookie_jar, cookie_template)
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
