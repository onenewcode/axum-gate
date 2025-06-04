use axum_gate::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use axum_gate::jwt::{JsonWebToken, JsonWebTokenOptions, RegisteredClaims};
use axum_gate::services::AccountInsertService;
use axum_gate::storage::memory::{MemoryAccountStorage, MemorySecretStorage};
use axum_gate::{Credentials, Group, Role, cookie};

use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use dotenv;
use tracing::debug;

const ISSUER: &str = "auth-node";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    debug!("Tracing initialized.");

    dotenv::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenv::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(JsonWebToken::new_with_options(JsonWebTokenOptions {
        enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(Header::default()),
        validation: Some(Validation::default()),
    }));
    debug!("JWT codec initialized.");

    let account_storage = Arc::new(MemoryAccountStorage::default());
    debug!("Account storage initialized.");
    let secrets_storage = Arc::new(MemorySecretStorage::default());
    debug!("Secrets storage initialized.");

    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .into_storages(Arc::clone(&account_storage), Arc::clone(&secrets_storage))
        .await
        .unwrap();
    debug!("Inserted Admin.");

    AccountInsertService::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![Role::Reporter])
        .with_groups(vec![Group::new("reporter")])
        .into_storages(Arc::clone(&account_storage), Arc::clone(&secrets_storage))
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    AccountInsertService::insert("user@example.com", "user_password")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("user")])
        .into_storages(Arc::clone(&account_storage), Arc::clone(&secrets_storage))
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = cookie::CookieBuilder::new("axum-gate", "").secure(true);

    let app = Router::new()
        .route(
            "/login",
            post({
                let mut registered_claims = RegisteredClaims::new(
                    ISSUER,
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
                );
                registered_claims.issuer = Some(ISSUER.to_string());
                let secrets_storage = Arc::clone(&secrets_storage);
                let account_storage = Arc::clone(&account_storage);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, request_credentials: Json<Credentials<String>>| {
                    axum_gate::route_handlers::login(
                        cookie_jar,
                        request_credentials,
                        registered_claims,
                        secrets_storage,
                        account_storage,
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
