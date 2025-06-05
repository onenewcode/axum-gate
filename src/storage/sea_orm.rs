//! Support for SQL database storage through [sea-orm](sea_orm).

use crate::hashing::VerificationResult;
use crate::secrets::Secret;
use crate::services::{AccountStorageService, HashingService, SecretStorageService};
use crate::utils::{AccessHierarchy, CommaSeparatedValue};
use crate::{
    Account, Credentials, Error, storage::sea_orm::models::account as seaorm_account,
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
pub struct SeaOrmStorage<Hasher> {
    db: DatabaseConnection,
    hasher: Hasher,
}

impl<Hasher> SeaOrmStorage<Hasher> {
    /// Creates a new instance from the given variables.
    pub fn new(db: &DatabaseConnection, hasher: Hasher) -> Self
    where
        Hasher: HashingService,
    {
        Self {
            db: db.clone(),
            hasher,
        }
    }
}

impl<Hasher, R, G> AccountStorageService<R, G> for SeaOrmStorage<Hasher>
where
    Hasher: HashingService,
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

impl<Hasher> SecretStorageService for SeaOrmStorage<Hasher>
where
    Hasher: HashingService,
{
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let hashed_secret = self
            .hasher
            .hash_value(&secret.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        let secret = Secret::new(&secret.account_id, &hashed_secret);

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
        let hashed_secret = self
            .hasher
            .hash_value(&secret.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        let secret = Secret::new(&secret.account_id, &hashed_secret);

        let model = models::credentials::ActiveModel::from(secret);
        model
            .update(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        Ok(())
    }

    async fn verify_secret(&self, credentials: Credentials<Uuid>) -> Result<VerificationResult> {
        let Some(model) = seaorm_credentials::Entity::find()
            .filter(seaorm_credentials::Column::AccountId.eq(credentials.user_id))
            .one(&self.db)
            .await
            .map_err(|e| Error::SecretStorage(e.to_string()))?
        else {
            return Ok(VerificationResult::Unauthorized);
        };
        tracing::debug!("Secret to verify: {}", &credentials.secret);

        self.hasher.verify_value(&credentials.secret, &model.secret)
    }
}
