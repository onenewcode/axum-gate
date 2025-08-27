use axum_gate::auth::AccountInsertService;
use axum_gate::http::cookie;
use axum_gate::jwt::{JsonWebToken, JwtClaims, RegisteredClaims, advanced::JsonWebTokenOptions};
use axum_gate::storage::SeaOrmRepository;
use axum_gate::utils::external::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use axum_gate::{Account, Credentials, Group, Role};

use std::sync::Arc;

use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use dotenv;
use sea_orm::{ConnectionTrait, DbBackend, DbConn, Schema};
use sea_query::table::TableCreateStatement;
use tracing::debug;

const DATABASE_URL: &str = "sqlite::memory:";
// Use the following if you want to see what is stored
//const DATABASE_URL: &str = "sqlite:auth-node.sqlite3?mode=rwc";

async fn setup_database_schema(db: &DbConn) {
    let schema = Schema::new(DbBackend::Sqlite);
    let stmt: TableCreateStatement =
        schema.create_table_from_entity(axum_gate::storage::models::credentials::Entity);
    db.execute(db.get_database_backend().build(&stmt))
        .await
        .expect("Could not create credentials table");
    let stmt: TableCreateStatement =
        schema.create_table_from_entity(axum_gate::storage::models::account::Entity);
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
        Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(jwt_options));

    // SQLite memory database connection
    let db = sea_orm::Database::connect(DATABASE_URL)
        .await
        .expect(&format!("Could not connect to {DATABASE_URL} database."));

    setup_database_schema(&db).await;

    let account_repository = Arc::new(SeaOrmRepository::new(&db));
    debug!("Account repository initialized.");
    let secrets_repository = Arc::clone(&account_repository);
    debug!("Secrets repository initialized.");

    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin.");

    AccountInsertService::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![Role::Reporter])
        .with_groups(vec![Group::new("reporter")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    AccountInsertService::insert("user@example.com", "user_password")
        .with_roles(vec![Role::User])
        .with_groups(vec![Group::new("user")])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = cookie::CookieBuilder::new("axum-gate", "").secure(true);

    let app = Router::new()
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    // same as in distributed example, so you can re-use the consumer_node
                    "auth-node",
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
                );
                let secrets_repository = Arc::clone(&secrets_repository);
                let account_repository = Arc::clone(&account_repository);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, request_credentials: Json<Credentials<String>>| {
                    axum_gate::auth::login(
                        cookie_jar,
                        request_credentials,
                        registered_claims,
                        secrets_repository,
                        account_repository,
                        jwt_codec,
                        cookie_template,
                    )
                }
            }),
        )
        .route(
            "/logout",
            get(move |cookie_jar| axum_gate::auth::logout(cookie_jar, cookie_template)),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
