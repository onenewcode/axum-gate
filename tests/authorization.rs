use axum_gate::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use axum_gate::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use axum_gate::AccountInsertService;
use axum_gate::memory::{MemoryAccountRepository, MemorySecretRepository};
use axum_gate::{Account, Credentials, Gate, Group, Role, cookie};
use http::HeaderValue;
use http::header;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Json};
use axum::http::{self, Request, StatusCode};
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tower::{Service, ServiceExt};
use tracing::debug;

/// Provides custom permissions for fine-grained access support.
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
#[non_exhaustive]
pub enum AdditionalPermission {
    ReadRepository,
    WriteRepository,
    ReadApi,
    WriteApi,
}
const ISSUER: &str = "auth-node";
const COOKIE_NAME: &str = "axum-gate";

async fn reporter(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn user(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn permissions(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}! Your permissions are: {:?}",
        user.user_id,
        user.roles,
        user.groups,
        user.permissions
            .iter()
            .map(|p| AdditionalPermission::try_from(p).expect("Permission does not exist."))
            .collect::<Vec<_>>()
    ))
}

async fn admin_group(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hi {} and welcome to the secret admin-group site on the consumer node, your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin(Extension(user): Extension<Account<Role, Group>>) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn build_storages() -> (
    Arc<MemoryAccountRepository<Role, Group>>,
    Arc<MemorySecretRepository>,
) {
    let account_repository = Arc::new(MemoryAccountRepository::from(vec![]));
    debug!("Account repository initialized.");
    let secrets_repository = Arc::new(MemorySecretRepository::default());
    debug!("Secrets repository initialized.");

    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![Role::Admin])
        .with_groups(vec![Group::new("admin")])
        .with_permissions(vec![AdditionalPermission::ReadApi])
        .into_repositories(Arc::clone(&account_repository), Arc::clone(&secrets_repository))
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
        .with_permissions(vec![AdditionalPermission::ReadApi])
        .into_repositories(Arc::clone(&account_repository), Arc::clone(&secrets_repository))
        .await
        .unwrap();
    debug!("Inserted User.");

    (account_repository, secrets_repository)
}

async fn setup_dummy_app() -> Router {
    let shared_secret = "AXUM_GATE_SHARED_SECRET";
    let jwt_codec = Arc::new(
        JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(JsonWebTokenOptions {
            enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
            dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
            header: Some(Header::default()),
            validation: Some(Validation::default()),
        }),
    );

    let (account_repository, secrets_repository) = build_storages().await;

    let cookie_template = cookie::CookieBuilder::new(COOKIE_NAME, "").secure(true);

    Router::new()
        .route("/admin", get(admin))
        .layer(
            Gate::new_cookie(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .grant_role_and_supervisor(Role::Admin),
        )
        .route(
            "/secret-admin-group",
            get(admin_group).layer(
                Gate::new_cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .grant_group(Group::new("admin")),
            ),
        )
        .route("/reporter", get(reporter))
        .layer(
            Gate::new_cookie(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .grant_role_and_supervisor(Role::Reporter),
        )
        .route(
            "/user",
            get(user).layer(
                Gate::new_cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .grant_role(Role::User),
            ),
        )
        .route(
            "/permissions",
            get(permissions).layer(
                Gate::new_cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .grant_permission(AdditionalPermission::ReadApi),
            ),
        )
        .route(
            "/login",
            post({
                let registered_claims = RegisteredClaims::new(
                    ISSUER,
                    (Utc::now() + TimeDelta::weeks(1)).timestamp() as u64,
                );
                let secrets_storage = Arc::clone(&secrets_storage);
                let account_storage = Arc::clone(&account_storage);
                let jwt_codec = Arc::clone(&jwt_codec);
                let cookie_template = cookie_template.clone();
                move |cookie_jar, Json(credentials): Json<Credentials<String>>| {
                    axum_gate::route_handlers::login(
                        cookie_jar,
                        credentials,
                        registered_claims,
                        secrets_repository,
                        account_repository,
                        jwt_codec,
                        cookie_template,
                    )
                }
            }),
        )
}

#[tokio::test]
async fn credentials() {
    let mut app = setup_dummy_app().await;

    let login_response = app
        .call(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&Credentials::new(
                        &"user@example.com".to_string(),
                        "wrong_user_password",
                    ))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::UNAUTHORIZED);

    let login_response = app
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&Credentials::new(
                        &"user@example.com".to_string(),
                        "user_password",
                    ))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
}

async fn assert_get_request(
    app: &mut Router,
    cookie_value: HeaderValue,
    route: &str,
    status: StatusCode,
) {
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(route)
        .header(header::COOKIE, cookie_value)
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.unwrap();
    assert_eq!(response.status(), status);
}

#[tokio::test]
async fn user_authorization() {
    let mut app = setup_dummy_app().await;

    let login_response = app
        .call(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&Credentials::new(
                        &"user@example.com".to_string(),
                        "user_password",
                    ))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let cookie_value = login_response.headers().get("set-cookie").unwrap();
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/admin",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/secret-admin-group",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/reporter",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(&mut app, cookie_value.clone(), "/user", StatusCode::OK).await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/permissions",
        StatusCode::OK,
    )
    .await;
}

#[tokio::test]
async fn admin_authorization() {
    let mut app = setup_dummy_app().await;

    let login_response = app
        .call(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&Credentials::new(
                        &"admin@example.com".to_string(),
                        "admin_password",
                    ))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let cookie_value = login_response.headers().get("set-cookie").unwrap();
    assert_get_request(&mut app, cookie_value.clone(), "/admin", StatusCode::OK).await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/secret-admin-group",
        StatusCode::OK,
    )
    .await;
    assert_get_request(&mut app, cookie_value.clone(), "/reporter", StatusCode::OK).await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/user",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/permissions",
        StatusCode::OK,
    )
    .await;
}

#[tokio::test]
async fn reporter_authorization() {
    let mut app = setup_dummy_app().await;

    let login_response = app
        .call(
            Request::builder()
                .method(http::Method::POST)
                .uri("/login")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(
                    serde_json::to_string(&Credentials::new(
                        &"reporter@example.com".to_string(),
                        "reporter_password",
                    ))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let cookie_value = login_response.headers().get("set-cookie").unwrap();
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/admin",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/secret-admin-group",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(&mut app, cookie_value.clone(), "/reporter", StatusCode::OK).await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/user",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        cookie_value.clone(),
        "/permissions",
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test]
async fn anonymous_authorization() {
    let mut app = setup_dummy_app().await;

    assert_get_request(
        &mut app,
        HeaderValue::from_static(""),
        "/admin",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        HeaderValue::from_static(""),
        "/secret-admin-group",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        HeaderValue::from_static(""),
        "/reporter",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        HeaderValue::from_static(""),
        "/user",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_get_request(
        &mut app,
        HeaderValue::from_static(""),
        "/permissions",
        StatusCode::UNAUTHORIZED,
    )
    .await;
}
