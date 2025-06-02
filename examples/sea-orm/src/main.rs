use axum::extract::Json;
use axum::routing::{Router, get, post};
use axum_gate::Account;
use axum_gate::Role;
use axum_gate::cookie;
use axum_gate::credentials::Credentials;
use axum_gate::jsonwebtoken::DecodingKey;
use axum_gate::jsonwebtoken::EncodingKey;
use axum_gate::jsonwebtoken::Header;
use axum_gate::jsonwebtoken::Validation;
use axum_gate::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use axum_gate::secrets::Argon2Hasher;
use axum_gate::storage::{
    CredentialsStorageService, PassportStorageService, sea_orm::SeaOrmStorage,
};
use chrono::{TimeDelta, Utc};
use dotenv;
use sea_orm::{ConnectionTrait, DbBackend, DbConn, Schema};
use sea_query::table::TableCreateStatement;
use std::sync::Arc;

const DATABASE_URL: &str = "sqlite::memory:";

async fn setup_database_schema(db: &DbConn) {
    let schema = Schema::new(DbBackend::Sqlite);
    let stmt: TableCreateStatement =
        schema.create_table_from_entity(axum_gate::storage::sea_orm::models::credentials::Entity);
    db.execute(db.get_database_backend().build(&stmt))
        .await
        .expect("Could not create credentials table");
    let stmt: TableCreateStatement =
        schema.create_table_from_entity(axum_gate::storage::sea_orm::models::account::Entity);
    db.execute(db.get_database_backend().build(&stmt))
        .await
        .expect("Could not create account table");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenv::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_options = JsonWebTokenOptions {
        enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(Header::default()),
        validation: Some(Validation::default()),
    };
    let jwt_codec =
        Arc::new(JsonWebToken::<JwtClaims<Account<i32, Role>>>::new_with_options(jwt_options));

    // SQLite memory database connection
    let db = sea_orm::Database::connect(DATABASE_URL)
        .await
        .expect(&format!("Could not connect to {DATABASE_URL} database."));

    setup_database_schema(&db).await;

    // setup dummy usernames
    let username_admin = "admin@example.com";
    let username_reporter = "reporter@example.com";
    let username_user = "user@example.com";

    let creds = Credentials::new(username_admin, "admin_password");
    let reporter_creds = Credentials::new(username_reporter, "reporter_password");
    let user_creds = Credentials::new(username_user, "user_password");

    let creds_storage = Arc::new(SeaOrmStorage::new(&db, Argon2Hasher::default()));
    let creds = creds_storage
        .store_credentials(creds)
        .await
        .expect("Could not insert creds.");
    let reporter_creds = creds_storage
        .store_credentials(reporter_creds)
        .await
        .expect("Could not insert reporter_creds.");
    let user_creds = creds_storage
        .store_credentials(user_creds)
        .await
        .expect("Could not insert user_creds.");

    let admin_passport = Account::new(username_admin, &["admin"], &[Role::Admin]);
    let reporter_passport = Account::new(username_reporter, &["reporter"], &[Role::Reporter]);
    let user_passport = Account::new(username_user, &["user"], &[Role::User]);

    let passport_storage = Arc::clone(&creds_storage);
    passport_storage
        .store_passport(&admin_passport)
        .await
        .expect("Could not insert admin passport.");
    passport_storage
        .store_passport(&reporter_passport)
        .await
        .expect("Could not insert reporter passport.");
    passport_storage
        .store_passport(&user_passport)
        .await
        .expect("Could not insert user passport.");

    let cookie_template = cookie::CookieBuilder::new("axum-gate", "").secure(true);

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    "auth-node", // same as in distributed example, so you can re-use the consumer_node
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
                );
                let credentials_verifier = Arc::clone(&creds_storage);
                let passport_storage = Arc::clone(&passport_storage);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, request_credentials: Json<Credentials<i32>>| {
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
