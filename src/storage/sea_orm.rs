//! Support for SQL database storage through [sea-orm].

use super::{CredentialsStorageService, PassportStorageService};
use crate::{
    AccessHierarchy, Account, CommaSeparatedValue, Error, credentials::Credentials,
    secrets::SecretsHashingService, storage::sea_orm::models::account::Entity as AccountEntity,
};

use std::collections::HashSet;

use sea_orm::{
    DatabaseConnection, EntityTrait,
    entity::{ActiveModelTrait, ActiveValue},
};
use serde::{Serialize, de::DeserializeOwned};

pub mod models;

/// Storage implementation for [sea-orm].
pub struct SeaOrmStorage<Hasher> {
    db: DatabaseConnection,
    hasher: Hasher,
}

impl<Hasher, R> PassportStorageService<Account<i32, R>> for SeaOrmStorage<Hasher>
where
    Hasher: SecretsHashingService,
    R: AccessHierarchy
        + Eq
        + std::hash::Hash
        + Serialize
        + DeserializeOwned
        + std::fmt::Display
        + Clone,
    HashSet<R>: CommaSeparatedValue,
{
    async fn passport(&self, passport_id: &i32) -> Result<Option<Account<i32, R>>, crate::Error> {
        let Some(model) = AccountEntity::find_by_id(*passport_id)
            .one(&self.db)
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?
        else {
            return Ok(None);
        };

        Ok(Some(
            Account::try_from(model).map_err(|e| Error::Storage(e.to_string()))?,
        ))
    }

    async fn store_passport(
        &self,
        passport: &Account<i32, R>,
    ) -> Result<Option<i32>, crate::Error> {
        let mut model = models::account::ActiveModel::from(passport.clone());
        model.id = ActiveValue::NotSet;
        let model = model
            .insert(&self.db)
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        Ok(Some(model.id))
    }

    async fn remove_passport(
        &self,
        passport_id: &i32,
    ) -> Result<Option<Account<i32, R>>, crate::Error> {
        let account: Option<Account<i32, R>> = self.passport(passport_id).await?;
        AccountEntity::delete_by_id(*passport_id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        Ok(account)
    }
}

impl<Hasher> CredentialsStorageService<i32> for SeaOrmStorage<Hasher>
where
    Hasher: SecretsHashingService,
{
    async fn store_credentials(&self, credentials: Credentials<i32>) -> Result<bool, Error> {
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let credentials = Credentials::new(&credentials.id, &secret);

        let model = models::credentials::ActiveModel::from(credentials);
        model
            .insert(&self.db)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(true)
    }

    /// The credentials `id` needs to be queried from the passport storage.
    async fn remove_credentials(&self, id: &i32) -> Result<bool, Error> {
        models::credentials::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(true)
    }

    async fn update_credentials(&self, credentials: Credentials<i32>) -> Result<(), Error> {
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let credentials = Credentials::new(&credentials.id, &secret);

        let model = models::credentials::ActiveModel::from(credentials);
        model
            .update(&self.db)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(())
    }
}

/*
impl<Hasher> CredentialsVerifierService for SeaOrmStorage<Hasher> where Hasher: SecretsHashingService
{}
 */
