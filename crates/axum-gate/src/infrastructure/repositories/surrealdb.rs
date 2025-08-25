//! Repository implementations that use surrealdb as backend.

use super::TableNames;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::Secret;
use crate::domain::values::VerificationResult;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::{AccountRepository, SecretRepository};
use crate::{
    Account, Credentials,
    errors::{DatabaseOperation, Error, InfrastructureError},
};

use std::default::Default;

use crate::errors::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;
use surrealdb::{Connection, RecordId, RecordIdKey, Surreal};
use uuid::Uuid;

/// Configurations to use with the [surrealdb] database.
#[derive(Clone, Debug)]
pub struct DatabaseScope {
    /// The table names of the database.
    pub table_names: TableNames,
    /// Namespace where data is stored.
    pub namespace: String,
    /// Database name where data is stored.
    pub database: String,
}

impl Default for DatabaseScope {
    fn default() -> Self {
        Self {
            table_names: TableNames::default(),
            namespace: "axum-gate".to_string(),
            database: "axum-gate".to_string(),
        }
    }
}

/// A repository that uses [surrealdb] as backend.
#[derive(Clone)]
pub struct SurrealDbRepository<S>
where
    S: Connection,
{
    db: Surreal<S>,
    scope_settings: DatabaseScope,
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    /// Creates a new repository that uses the given database connection limited by the given scope.
    pub fn new(db: Surreal<S>, scope_settings: DatabaseScope) -> Self {
        Self { db, scope_settings }
    }

    /// Sets the correct namespace and database to use.
    async fn use_ns_db(&self) -> Result<()> {
        self.db
            .use_ns(&self.scope_settings.namespace)
            .use_db(&self.scope_settings.database)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Connect,
                    message: format!("Failed to set namespace/database: {}", e),
                    table: None,
                    record_id: None,
                })
            })
    }
}

impl<R, G, S> AccountRepository<R, G> for SurrealDbRepository<S>
where
    R: AccessHierarchy + Eq + DeserializeOwned + Serialize + 'static,
    G: Serialize + DeserializeOwned + Eq + 'static,
    S: Connection,
{
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        self.use_ns_db().await?;
        let db_account: Option<Account<R, G>> = self
            .db
            .select(RecordId::from_table_key(
                &self.scope_settings.table_names.accounts,
                user_id,
            ))
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to query account by user_id: {}", e),
                    table: Some(self.scope_settings.table_names.accounts.clone()),
                    record_id: Some(user_id.to_string()),
                })
            })?;
        Ok(db_account)
    }

    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        self.use_ns_db().await?;
        let record_id =
            RecordId::from_table_key(&self.scope_settings.table_names.accounts, &account.user_id);
        let user_id = account.user_id.clone();
        let db_account: Option<Account<R, G>> = self
            .db
            .insert(record_id)
            .content(account)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Insert,
                    message: format!("Could not insert account: {}", e),
                    table: Some(self.scope_settings.table_names.accounts.clone()),
                    record_id: Some(user_id),
                })
            })?;
        Ok(db_account)
    }

    async fn delete_account(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        self.use_ns_db().await?;
        let db_account: Option<Account<R, G>> = self
            .db
            .delete(RecordId::from_table_key(
                &self.scope_settings.table_names.accounts,
                user_id,
            ))
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Delete,
                    message: format!("Failed to delete account: {}", e),
                    table: Some(self.scope_settings.table_names.accounts.clone()),
                    record_id: Some(user_id.to_string()),
                })
            })?;
        Ok(db_account)
    }

    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        self.use_ns_db().await?;
        let record_id =
            RecordId::from_table_key(&self.scope_settings.table_names.accounts, &account.user_id);
        let db_account: Option<Account<R, G>> = self.db.update(&record_id).content(account).await?;
        Ok(db_account)
    }
}

impl<S> SecretRepository for SurrealDbRepository<S>
where
    S: Connection,
{
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        self.use_ns_db().await?;

        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            secret.account_id,
        );

        let account_id = secret.account_id;
        let db_credentials: Option<Secret> = self
            .db
            .insert(&record_id)
            .content(secret)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Insert,
                    message: format!("Failed to store secret: {}", e),
                    table: Some(self.scope_settings.table_names.credentials.clone()),
                    record_id: Some(account_id.to_string()),
                })
            })?;
        Ok(db_credentials.is_some())
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(&self.scope_settings.table_names.credentials, *id);
        let result: Option<Secret> = self.db.delete(record_id).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Delete,
                message: format!("Failed to delete secret: {}", e),
                table: Some(self.scope_settings.table_names.credentials.clone()),
                record_id: Some(id.to_string()),
            })
        })?;
        Ok(result.is_some())
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        self.use_ns_db().await?;

        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            secret.account_id,
        );
        let account_id = secret.account_id;
        let _: Option<Secret> = self
            .db
            .update(record_id)
            .content(secret)
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Update,
                    message: format!("Failed to update secret: {}", e),
                    table: Some(self.scope_settings.table_names.credentials.clone()),
                    record_id: Some(account_id.to_string()),
                })
            })?;
        Ok(())
    }
}

impl<S, Id> CredentialsVerifier<Id> for SurrealDbRepository<S>
where
    S: Connection,
    Id: Into<RecordIdKey>,
{
    async fn verify_credentials(&self, credentials: Credentials<Id>) -> Result<VerificationResult> {
        self.use_ns_db().await?;
        let record_id =
            RecordId::from_table_key(&self.scope_settings.table_names.credentials, credentials.id);
        let query = "crypto::argon2::compare((SELECT secret from only $record_id).secret, type::string($request_secret))".to_string();

        let mut response = self
            .db
            .query(query)
            .bind(("record_id", record_id))
            .bind(("request_secret", credentials.secret))
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to verify credentials: {}", e),
                    table: Some(self.scope_settings.table_names.credentials.clone()),
                    record_id: None,
                })
            })?;
        let result: Option<bool> = response.take(0).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Query,
                message: format!("Failed to extract verification result: {}", e),
                table: Some(self.scope_settings.table_names.credentials.clone()),
                record_id: None,
            })
        })?;

        Ok(VerificationResult::from(result.unwrap_or(false)))
    }
}

#[test]
fn secret_repository() {
    tokio_test::block_on(async move {
        use crate::infrastructure::hashing::Argon2Hasher;
        use surrealdb::engine::local::Mem;

        // create a repository
        let db = Surreal::new::<Mem>(())
            .await
            .expect("Could not create in memory database.");
        let creds_repository = SurrealDbRepository::new(db, DatabaseScope::default());
        let id = Uuid::now_v7();

        let creds = Secret::new(&id, "admin_password", Argon2Hasher).unwrap();

        creds_repository.store_secret(creds).await.unwrap();

        let creds_to_verify = Credentials::new(&id, "admin_password");
        let wrong_creds = Credentials::new(&id, "admin_passwordwrong");
        assert_eq!(
            VerificationResult::Unauthorized,
            creds_repository
                .verify_credentials(wrong_creds)
                .await
                .unwrap()
        );
        assert_eq!(
            VerificationResult::Ok,
            creds_repository
                .verify_credentials(creds_to_verify)
                .await
                .unwrap()
        );
    })
}

#[test]
fn account_repository() {
    tokio_test::block_on(async move {
        use crate::{Account, Group, Role};
        use surrealdb::engine::local::Mem;

        let db = Surreal::new::<Mem>(())
            .await
            .expect("Could not create in memory database.");
        let account_repository = SurrealDbRepository::new(db, DatabaseScope::default());

        let account = Account::new(
            "mymail@accountid-example.com",
            &[Role::Admin],
            &[Group::new("admin"), Group::new("audio")],
        );
        let account = account_repository
            .store_account(account)
            .await
            .unwrap()
            .unwrap();

        let Some(db_account): Option<Account<Role, Group>> = account_repository
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap()
        else {
            panic!("Account not found in database.");
        };

        assert_eq!(account.account_id, db_account.account_id);

        let Some(account): Option<Account<Role, Group>> = account_repository
            .delete_account(&account.user_id)
            .await
            .unwrap()
        else {
            panic!("Removing passport was not successful.");
        };

        let account: Option<Account<Role, Group>> = account_repository
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap();
        if account.is_some() {
            panic!("Passport is still available althoug it should not.");
        };
    })
}
