//! Support for SQL database storage through [sea-orm](sea_orm).

use crate::Credentials;
use crate::hashing::{Argon2Hasher, VerificationResult};
use crate::secrets::Secret;
use crate::services::{AccountStorageService, CredentialsVerifierService, SecretStorageService};
use crate::utils::{AccessHierarchy, CommaSeparatedValue};
use crate::{
    Account, Error, storage::sea_orm::models::account as seaorm_account,
    storage::sea_orm::models::credentials as seaorm_credentials,
};

use anyhow::Result;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    entity::{ActiveModelTrait, ActiveValue},
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub mod models;

/// Storage implementation for [sea-orm](sea_orm).
pub struct SeaOrmStorage {
    db: DatabaseConnection,
}

impl SeaOrmStorage {
    /// Creates a new storage that uses the given database connection as backend.
    pub fn new(db: &DatabaseConnection) -> Self {
        Self { db: db.clone() }
    }
}

impl<R, G> AccountStorageService<R, G> for SeaOrmStorage
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
            .map_err(|e| Error::AccountStorage(e.to_string()))?
        else {
            return Ok(None);
        };

        Ok(Some(
            Account::try_from(model).map_err(|e| Error::Storage(e.to_string()))?,
        ))
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let mut model = seaorm_account::ActiveModel::from(account);
        model.id = ActiveValue::NotSet;
        let model = model
            .insert(&self.db)
            .await
            .map_err(|e| Error::AccountStorage(e.to_string()))?;
        Ok(Some(
            Account::try_from(model).map_err(|e| Error::Storage(e.to_string()))?,
        ))
    }

    async fn delete_account(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let Some(model) = seaorm_account::Entity::find()
            .filter(seaorm_account::Column::UserId.eq(user_id))
            .one(&self.db)
            .await
            .map_err(|e| Error::AccountStorage(e.to_string()))?
        else {
            return Ok(None);
        };

        seaorm_account::Entity::delete_by_id(model.id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::AccountStorage(e.to_string()))?;

        Ok(Some(
            Account::try_from(model).map_err(|e| Error::AccountStorage(e.to_string()))?,
        ))
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let Some(db_account): Option<Account<R, G>> =
            self.query_account_by_user_id(&account.user_id).await?
        else {
            return Ok(None);
        };
        let mut db_account: seaorm_account::ActiveModel = db_account.into();
        db_account.user_id = ActiveValue::Set(account.user_id);
        db_account.groups = ActiveValue::Set(account.groups.into_csv());
        db_account.roles = ActiveValue::Set(account.roles.into_csv());

        let model = db_account
            .update(&self.db)
            .await
            .map_err(|e| Error::AccountStorage(e.to_string()))?;
        Ok(Some(
            Account::try_from(model).map_err(|e| Error::AccountStorage(e.to_string()))?,
        ))
    }
}

impl SecretStorageService for SeaOrmStorage {
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let model = seaorm_credentials::ActiveModel::from(secret);
        let _ = model
            .insert(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        Ok(true)
    }

    /// The credentials `account_id` needs to be queried from the account storage.
    async fn delete_secret(&self, account_id: &Uuid) -> Result<bool> {
        let Some(model) = seaorm_credentials::Entity::find()
            .filter(seaorm_credentials::Column::AccountId.eq(*account_id))
            .one(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?
        else {
            return Ok(false);
        };

        seaorm_credentials::Entity::delete_by_id(model.id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        Ok(true)
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        let model = models::credentials::ActiveModel::from(secret);
        model
            .update(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        Ok(())
    }
}

impl CredentialsVerifierService<Uuid> for SeaOrmStorage {
    async fn verify_credentials(
        &self,
        credentials: Credentials<Uuid>,
    ) -> Result<VerificationResult> {
        let Some(model) = seaorm_credentials::Entity::find()
            .filter(seaorm_credentials::Column::AccountId.eq(credentials.id))
            .one(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?
        else {
            return Ok(VerificationResult::Unauthorized);
        };

        let secret = Secret::from_hashed(&model.account_id, &model.secret);
        secret.verify(&credentials.secret, Argon2Hasher)
    }
}
