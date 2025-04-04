use axum::extract::Extension;
use axum::extract::Json;
use axum::routing::{Router, get, post};
use axum_gate::credentials::Credentials;
use axum_gate::gate::Gate;
use axum_gate::jwt::JsonWebToken;
use axum_gate::jwt::RegisteredClaims;
use axum_gate::passport::BasicPassport;
use axum_gate::roles::BasicRole;
use axum_gate::secrets::Argon2Hasher;
use axum_gate::storage::{CredentialsMemoryStorage, PassportMemoryStorage};
use std::sync::Arc;

async fn index() -> Result<String, ()> {
    Ok("Hello axum!".to_string())
}

async fn reporter(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {}, your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

async fn user(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {}, your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

async fn admin(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {}, your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let hasher = Arc::new(Argon2Hasher::default());
    let creds = Credentials::new(
        "admin@example.com".to_string(),
        "admin_password".to_string().as_bytes(),
    )
    .hash_secret(&*hasher)
    .unwrap();
    let reporter_creds = Credentials::new(
        "reporter@example.com".to_string(),
        "reporter_password".to_string().as_bytes(),
    )
    .hash_secret(&*hasher)
    .unwrap();
    let user_creds = Credentials::new(
        "user@example.com".to_string(),
        "user_password".to_string().as_bytes(),
    )
    .hash_secret(&*hasher)
    .unwrap();
    let creds_storage = Arc::new(CredentialsMemoryStorage::from(vec![
        creds.clone(),
        user_creds.clone(),
        reporter_creds.clone(),
    ]));

    let admin_passport = BasicPassport::new(&creds.id, &["admin"], &[BasicRole::Admin])
        .expect("Creating passport failed.");
    let reporter_passport =
        BasicPassport::new(&reporter_creds.id, &["reporter"], &[BasicRole::Reporter])
            .expect("Creating passport failed.");
    let user_passport = BasicPassport::new(&user_creds.id, &["user"], &[BasicRole::User])
        .expect("Creating passport failed.");
    let passport_storage = Arc::new(PassportMemoryStorage::from(vec![
        admin_passport,
        user_passport,
        reporter_passport,
    ]));
    let jwt_codec = Arc::new(JsonWebToken::default());

    let app = Router::new()
        .route("/admin", get(admin))
        .layer(Gate::new((*jwt_codec).clone()).with_minimum_role(BasicRole::Admin))
        .route("/reporter", get(reporter))
        .layer(Gate::new((*jwt_codec).clone()).with_minimum_role(BasicRole::Reporter))
        .route(
            "/user",
            get(user).layer(Gate::new((*jwt_codec).clone()).with_role(BasicRole::User)),
        )
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
        .route("/logout", get(axum_gate::route_handlers::logout))
        .route("/", get(index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
