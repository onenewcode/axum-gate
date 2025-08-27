//! Support for SQL database repository through [sea-orm](sea_orm).

use crate::domain::traits::{AccessHierarchy, CommaSeparatedValue};
use crate::domain::values::Secret;
use crate::domain::values::VerificationResult;
use crate::errors::{DatabaseOperation, Error, InfrastructureError};
use crate::infrastructure::hashing::Argon2Hasher;
use crate::infrastructure::repositories::sea_orm::models::account as seaorm_account;
use crate::infrastructure::repositories::sea_orm::models::credentials as seaorm_credentials;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::{AccountRepository, SecretRepository};
use crate::prelude::{Account, Credentials};

use crate::errors::Result;
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
}

impl SeaOrmRepository {
    /// Creates a new repository that uses the given database connection as backend.
    pub fn new(db: &DatabaseConnection) -> Self {
        Self { db: db.clone() }
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

    /// The credentials `account_id` needs to be queried from the account repository.
    async fn delete_secret(&self, account_id: &Uuid) -> Result<bool> {
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
            return Ok(false);
        };

        seaorm_credentials::Entity::delete_by_id(model.id)
            .exec(&self.db)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Delete,
                    message: format!("Failed to delete secret: {}", e),
                    table: Some("credentials".to_string()),
                    record_id: Some(model.account_id.to_string()),
                })
            })?;
        Ok(true)
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
        use crate::ports::auth::HashingService;
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

        // Determine user existence and prepare hash for verification using constant-time operations
        let (stored_secret_str, user_exists_choice) = match model_result {
            Some(model) => (model.secret, Choice::from(1u8)),
            None => {
                // Use a realistic dummy Argon2 hash for constant-time operation
                let dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3ODkwYWJjZGVmZ2hpams$+U4VpzOTOuH3Lz3dN2CX2z6VZhUZP1c1xN1y2Z3Z4aA".to_string();
                (dummy_hash, Choice::from(0u8))
            }
        };

        // ALWAYS perform Argon2 verification (constant time regardless of user existence)
        let hasher = Argon2Hasher;
        let hash_verification_result =
            hasher.verify_value(&credentials.secret, &stored_secret_str)?;

        // Convert hash verification result to Choice for constant-time operations
        let hash_matches_choice = Choice::from(match hash_verification_result {
            VerificationResult::Ok => 1u8,
            VerificationResult::Unauthorized => 0u8,
        });

        // Combine results using constant-time AND operation
        // Success only if: user exists AND password hash matches
        let final_success_choice = user_exists_choice & hash_matches_choice;

        // Convert back to VerificationResult
        let final_result = if bool::from(final_success_choice) {
            VerificationResult::Ok
        } else {
            VerificationResult::Unauthorized
        };

        Ok(final_result)
    }
}
