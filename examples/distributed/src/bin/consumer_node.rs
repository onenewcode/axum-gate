use axum::extract::Extension;
use axum::routing::{Router, get};
use axum_gate::BasicGroup;
use axum_gate::Gate;
use axum_gate::cookie;
use axum_gate::jsonwebtoken::DecodingKey;
use axum_gate::jsonwebtoken::EncodingKey;
use axum_gate::jsonwebtoken::Header;
use axum_gate::jsonwebtoken::Validation;
use axum_gate::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};
use axum_gate::passport::BasicPassport;
use axum_gate::roles::BasicRole;
use dotenv;
use std::sync::Arc;

async fn index() -> Result<String, ()> {
    Ok("Hello consumer!".to_string())
}

async fn reporter(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

async fn user(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

async fn admin_group(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hi {} and welcome to the secret admin-group site on the consumer node, your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

async fn admin(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.id, user.roles, user.groups
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenv::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<BasicPassport>>::new_with_options(
        JsonWebTokenOptions {
            enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
            dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
            header: Some(Header::default()),
            validation: Some(Validation::default()),
        },
    ));
    let cookie_template = cookie::CookieBuilder::new("axum-gate", "").secure(true);

    let app = Router::new()
        .route("/admin", get(admin))
        .layer(
            Gate::new(Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .grant_role_and_supervisor(BasicRole::Admin),
        )
        .route(
            "/secret-admin-group",
            get(admin_group).layer(
                Gate::new(Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    // to_string required, because BasicPassport::Group is a String
                    .grant_group(BasicGroup::new("admin")),
            ),
        )
        .route("/reporter", get(reporter))
        .layer(
            Gate::new(Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .grant_role_and_supervisor(BasicRole::Reporter),
        )
        .route(
            "/user",
            get(user).layer(
                Gate::new(Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .grant_role(BasicRole::User),
            ),
        )
        .route("/", get(index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
