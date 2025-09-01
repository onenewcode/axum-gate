use distributed::{ApiPermission, AppPermissions, PermissionHelper, RepositoryPermission};

use axum_gate::auth::PermissionId;
use axum_gate::http::cookie;
use axum_gate::jwt::{JsonWebToken, JwtClaims, advanced::JsonWebTokenOptions};
use axum_gate::prelude::{AccessPolicy, Account, Gate, Group, Role};
use axum_gate::utils::external::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};

use std::sync::Arc;

use axum::extract::Extension;
use axum::routing::{Router, get};
use dotenv;

const ISSUER: &str = "auth-node";

async fn index() -> Result<String, ()> {
    Ok("Hello consumer!".to_string())
}

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
    // Demonstrate zero-sync permission checking
    let has_read_api = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Api(ApiPermission::Read),
    );
    let has_write_api = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Api(ApiPermission::Write),
    );
    let has_read_repo = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Repository(RepositoryPermission::Read),
    );
    let has_write_repo = PermissionHelper::has_permission(
        user.permissions.as_ref(),
        &AppPermissions::Repository(RepositoryPermission::Write),
    );
    let is_admin = PermissionHelper::is_admin(user.permissions.as_ref());

    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!\n\
        Zero-Sync Permission Analysis:\n\
        - Read API: {}\n\
        - Write API: {}\n\
        - Read Repository: {}\n\
        - Write Repository: {}\n\
        - Admin Access: {}\n\
        Raw permission bitmap: {:?}",
        user.user_id,
        user.roles,
        user.groups,
        has_read_api,
        has_write_api,
        has_read_repo,
        has_write_repo,
        is_admin,
        user.permissions.iter().collect::<Vec<_>>()
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    dotenv::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenv::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_codec = Arc::new(
        JsonWebToken::<JwtClaims<Account<Role, Group>>>::new_with_options(JsonWebTokenOptions {
            enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
            dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
            header: Some(Header::default()),
            validation: Some(Validation::default()),
        }),
    );
    let cookie_template = axum_gate::prelude::CookieTemplateBuilder::recommended().build();

    let app = Router::new()
        .route("/admin", get(admin))
        .layer(
            Gate::cookie_deny_all(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .with_policy(AccessPolicy::require_role_or_supervisor(Role::Admin)),
        )
        .route(
            "/secret-admin-group",
            get(admin_group).layer(
                Gate::cookie_deny_all(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_group(Group::new("admin"))),
            ),
        )
        .route("/reporter", get(reporter))
        .layer(
            Gate::cookie_deny_all(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .with_policy(AccessPolicy::require_role_or_supervisor(Role::Reporter)),
        )
        .route(
            "/user",
            get(user).layer(
                Gate::cookie_deny_all(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_role(Role::User)),
            ),
        )
        .route(
            "/permissions",
            get(permissions).layer(
                Gate::cookie_deny_all(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_permission(PermissionId::from(
                        AppPermissions::Api(ApiPermission::Read).as_str(),
                    ))),
            ),
        )
        .route("/", get(index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
