use axum_gate::advanced::AccessHierarchy;
use axum_gate::auth::AccountInsertService;
use axum_gate::integrations::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use axum_gate::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims, RegisteredClaims};
use axum_gate::prelude::{AccessPolicy, Account, Credentials, Gate};
use axum_gate::storage::{MemoryAccountRepository, MemorySecretRepository};

use std::sync::Arc;

use axum::Extension;
use axum::extract::Json;
use axum::routing::{Router, get, post};
use chrono::{TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub const ISSUER: &str = "auth-node";

/// A custom role definition.
#[derive(
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Debug,
    strum::Display,
)]
pub enum CustomRoleDefinition {
    #[default]
    Novice,
    Experienced,
    Expert,
}

impl AccessHierarchy for CustomRoleDefinition {}

/// A custom group definition.
#[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize, Debug)]
pub enum CustomGroupDefinition {
    Maintenance,
    Operations,
    Administration,
}

impl CustomGroupDefinition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::Operations => "operations",
            Self::Administration => "administration",
        }
    }
}

async fn reporter(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn user(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hello {} and welcome to the consumer node. Your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin_group(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
    Ok(format!(
        "Hi {} and welcome to the secret admin-group site on the consumer node, your roles are {:?} and you are member of groups {:?}!",
        user.user_id, user.roles, user.groups
    ))
}

async fn admin(
    Extension(user): Extension<Account<CustomRoleDefinition, CustomGroupDefinition>>,
) -> Result<String, ()> {
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

    dotenvy::dotenv().expect("Could not read .env file.");
    let shared_secret =
        dotenvy::var("AXUM_GATE_SHARED_SECRET").expect("AXUM_GATE_SHARED_SECRET env var not set.");
    let jwt_options = JsonWebTokenOptions {
        enc_key: EncodingKey::from_secret(shared_secret.as_bytes()),
        dec_key: DecodingKey::from_secret(shared_secret.as_bytes()),
        header: Some(Header::default()),
        validation: Some(Validation::default()),
    };
    let jwt_codec = Arc::new(JsonWebToken::<
        JwtClaims<Account<CustomRoleDefinition, CustomGroupDefinition>>,
    >::new_with_options(jwt_options));

    let account_repository = Arc::new(MemoryAccountRepository::from(vec![]));
    debug!("Account repository initialized.");
    let secrets_repository = Arc::new(MemorySecretRepository::from(vec![]));
    debug!("Secrets repository initialized.");

    AccountInsertService::insert("admin@example.com", "admin_password")
        .with_roles(vec![CustomRoleDefinition::Expert])
        .with_groups(vec![CustomGroupDefinition::Maintenance])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Admin.");

    AccountInsertService::insert("reporter@example.com", "reporter_password")
        .with_roles(vec![CustomRoleDefinition::Experienced])
        .with_groups(vec![CustomGroupDefinition::Operations])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted Reporter.");

    AccountInsertService::insert("user@example.com", "user_password")
        .with_roles(vec![CustomRoleDefinition::Novice])
        .with_groups(vec![CustomGroupDefinition::Administration])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secrets_repository),
        )
        .await
        .unwrap();
    debug!("Inserted User.");

    let cookie_template = axum_gate::prelude::CookieTemplateBuilder::recommended().build();

    let app = Router::new()
        .route("/admin", get(admin))
        .layer(
            Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                .with_cookie_template(cookie_template.clone())
                .with_policy(AccessPolicy::require_role(CustomRoleDefinition::Expert)),
        )
        .route(
            "/secret-admin-group",
            get(admin_group).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_group(
                        CustomGroupDefinition::Maintenance,
                    )),
            ),
        )
        .route(
            "/reporter",
            get(reporter).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_role_or_supervisor(
                        CustomRoleDefinition::Experienced,
                    )),
            ),
        )
        .route(
            "/user",
            get(user).layer(
                Gate::cookie(ISSUER, Arc::clone(&jwt_codec))
                    .with_cookie_template(cookie_template.clone())
                    .with_policy(AccessPolicy::require_role(CustomRoleDefinition::Novice)),
            ),
        )
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
                move |cookie_jar, Json(credentials): Json<Credentials<String>>| {
                    axum_gate::auth::login(
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
