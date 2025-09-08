//! Support for SQL database repository through [sea-orm](sea_orm).
//!
//! This repository includes constant-time credential verification to
//! mitigate user enumeration via timing differences. A dummy Argon2
//! hash (built with the active build-mode preset) is precomputed at
//! construction and used whenever a secret for a given account id
//! does not exist, ensuring the Argon2 verification path is always
//! executed.

use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::{AccessHierarchy, CommaSeparatedValue};
use crate::domain::values::{Secret, VerificationResult};
use crate::errors::{Error, InfrastructureError, Result};
use crate::infrastructure::errors::DatabaseOperation;
use crate::infrastructure::hashing::Argon2Hasher;
use crate::infrastructure::repositories::sea_orm::models::{
    account as seaorm_account, credentials as seaorm_credentials,
};
use crate::ports::auth::{CredentialsVerifier, HashingService};
use crate::ports::repositories::{AccountRepository, SecretRepository};

use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    entity::{ActiveModelTrait, ActiveValue},
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub mod models;

/// Repository implementation for [sea-orm](sea_orm).
pub struct SeaOrmRepository {
    db: DatabaseConnection,
    /// Precomputed dummy Argon2 hash used for nonexistent accounts to keep
    /// verification timing consistent.
    dummy_hash: String,
}

impl SeaOrmRepository {
    /// Creates a new repository that uses the given database connection as backend.
    pub fn new(db: &DatabaseConnection) -> Self {
        let hasher = Argon2Hasher::default();
        let dummy_hash = hasher
            .hash_value("dummy_password")
            .expect("Failed to generate dummy Argon2 hash");
        Self {
            db: db.clone(),
            dummy_hash,
        }
    }
}

impl<R, G> AccountRepository<R, G> for SeaOrmRepository
where
    R: AccessHierarchy + Eq + Serialize + DeserializeOwned + std::fmt::Display + Clone,
    G: Eq + Clone,
    Vec<R>: CommaSeparatedValue,
    Vec<G>: CommaSeparatedValue,
{
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let Some(model) = seaorm_account::Entity::find()
            .filter(seaorm_account::Column::UserId.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to query account by user_id: {}", e),
                    table: Some("accounts".to_string()),
                    record_id: Some(user_id.to_string()),
                })
            })?
        else {
            return Ok(None);
        };

        Ok(Some(Account::try_from(model).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Query,
                message: format!("Failed to convert database model to Account: {}", e),
                table: Some("accounts".to_string()),
                record_id: Some(user_id.to_string()),
            })
        })?))
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let mut model = seaorm_account::ActiveModel::from(account);
        model.id = ActiveValue::NotSet;
        let model = model.insert(&self.db).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Insert,
                message: format!("Failed to insert account: {}", e),
                table: Some("accounts".to_string()),
                record_id: None,
            })
        })?;
        Ok(Some(Account::try_from(model).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Insert,
                message: format!("Failed to convert inserted model to Account: {}", e),
                table: Some("accounts".to_string()),
                record_id: None,
            })
        })?))
    }

    async fn delete_account(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let Some(model) = seaorm_account::Entity::find()
            .filter(seaorm_account::Column::UserId.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to query account for deletion: {}", e),
                    table: Some("accounts".to_string()),
                    record_id: Some(user_id.to_string()),
                })
            })?
        else {
            return Ok(None);
        };

        seaorm_account::Entity::delete_by_id(model.id)
            .exec(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Delete,
                    message: format!("Failed to delete account: {}", e),
                    table: Some("accounts".to_string()),
                    record_id: Some(user_id.to_string()),
                })
            })?;

        Ok(Some(Account::try_from(model).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Delete,
                message: format!("Failed to convert deleted model to Account: {}", e),
                table: Some("accounts".to_string()),
                record_id: Some(user_id.to_string()),
            })
        })?))
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let Some(db_account): Option<Account<R, G>> =
            self.query_account_by_user_id(&account.user_id).await?
        else {
            return Ok(None);
        };
        let user_id = account.user_id.clone();
        let mut db_account: seaorm_account::ActiveModel = db_account.into();
        db_account.user_id = ActiveValue::Set(account.user_id);
        db_account.groups = ActiveValue::Set(account.groups.into_csv());
        db_account.roles = ActiveValue::Set(account.roles.into_csv());

        let model = db_account.update(&self.db).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Update,
                message: format!("Failed to update account: {}", e),
                table: Some("accounts".to_string()),
                record_id: Some(user_id.clone()),
            })
        })?;
        Ok(Some(Account::try_from(model).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Update,
                message: format!("Failed to convert updated model to Account: {}", e),
                table: Some("accounts".to_string()),
                record_id: Some(user_id),
            })
        })?))
    }
}

impl SecretRepository for SeaOrmRepository {
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let account_id = secret.account_id;
        let model = seaorm_credentials::ActiveModel::from(secret);
        let _ = model.insert(&self.db).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Insert,
                message: format!("Failed to store secret: {}", e),
                table: Some("credentials".to_string()),
                record_id: Some(account_id.to_string()),
            })
        })?;
        Ok(true)
    }

    /// Removes and returns the secret for the given account id.
    async fn delete_secret(&self, account_id: &Uuid) -> Result<Option<Secret>> {
        let Some(model) = seaorm_credentials::Entity::find()
            .filter(seaorm_credentials::Column::AccountId.eq(*account_id))
            .one(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to query secret for deletion: {}", e),
                    table: Some("credentials".to_string()),
                    record_id: Some(account_id.to_string()),
                })
            })?
        else {
            return Ok(None);
        };

        seaorm_credentials::Entity::delete_by_id(model.id)
            .exec(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Delete,
                    message: format!("Failed to delete secret: {}", e),
                    table: Some("credentials".to_string()),
                    record_id: Some(account_id.to_string()),
                })
            })?;

        Ok(Some(Secret {
            account_id: model.account_id,
            secret: model.secret,
        }))
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        let account_id = secret.account_id;
        let model = models::credentials::ActiveModel::from(secret);
        model.update(&self.db).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Update,
                message: format!("Failed to update secret: {}", e),
                table: Some("credentials".to_string()),
                record_id: Some(account_id.to_string()),
            })
        })?;
        Ok(())
    }
}

impl CredentialsVerifier<Uuid> for SeaOrmRepository {
    async fn verify_credentials(
        &self,
        credentials: Credentials<Uuid>,
    ) -> Result<VerificationResult> {
        use subtle::Choice;

        let model_result = seaorm_credentials::Entity::find()
            .filter(seaorm_credentials::Column::AccountId.eq(credentials.id))
            .one(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to query credentials for verification: {}", e),
                    table: Some("credentials".to_string()),
                    record_id: Some(credentials.id.to_string()),
                })
            })?;

        // Select stored or dummy hash (always perform Argon2 verify)
        let (stored_secret_str, user_exists_choice) = match model_result {
            Some(model) => (model.secret, Choice::from(1u8)),
            None => (self.dummy_hash.clone(), Choice::from(0u8)),
        };

        // Perform Argon2 verification locally (constant work)
        let hasher = Argon2Hasher::default();
        let hash_verification_result =
            hasher.verify_value(&credentials.secret, &stored_secret_str)?;

        let hash_matches_choice = Choice::from(match hash_verification_result {
            VerificationResult::Ok => 1u8,
            VerificationResult::Unauthorized => 0u8,
        });

        let final_success_choice = user_exists_choice & hash_matches_choice;

        let final_result = if bool::from(final_success_choice) {
            VerificationResult::Ok
        } else {
            VerificationResult::Unauthorized
        };

        Ok(final_result)
    }
}
