//! Support for SQL database storage through [sea-orm].

use super::{CredentialsStorageService, PassportStorageService};
use crate::{
    Account, Error, secrets::SecretsHashingService,
    storage::sea_orm::models::account::Entity as AccountEntity,
};

use sea_orm::{
    DatabaseConnection, EntityTrait,
    entity::{ActiveModelTrait, ActiveValue},
};

pub mod models;

/// Storage implementation for [sea-orm].
pub struct SeaOrmStorage<Hasher> {
    db: DatabaseConnection,
    hasher: Hasher,
}

impl<Hasher> PassportStorageService<Account<i32, String>> for SeaOrmStorage<Hasher>
where
    Hasher: SecretsHashingService,
{
    async fn passport(
        &self,
        passport_id: &i32,
    ) -> Result<Option<Account<i32, String>>, crate::Error> {
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
        passport: &Account<i32, String>,
    ) -> Result<Option<i32>, crate::Error> {
        let mut model = models::account::ActiveModel::from(passport.clone());
        model.id = ActiveValue::NotSet;
        let model = model
            .insert(&self.db)
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        Ok(Some(model.id))
    }

    async fn remove_passport(&self, passport_id: &i32) -> Result<bool, crate::Error> {
        AccountEntity::delete_by_id(*passport_id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        Ok(true)
    }
}

impl<Hasher> CredentialsStorageService<i32> for SeaOrmStorage<Hasher> {
    async fn store_credentials(
        &self,
        credentials: crate::credentials::Credentials<i32>,
    ) -> Result<bool, Error> {
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

    async fn update_credentials(
        &self,
        credentials: crate::credentials::Credentials<i32>,
    ) -> Result<(), Error> {
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
