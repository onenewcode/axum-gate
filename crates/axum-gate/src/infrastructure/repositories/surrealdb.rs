//! Repository implementations that use surrealdb as backend.

use super::TableNames;
use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::{Secret, VerificationResult};
use crate::errors::{DatabaseOperation, Error, InfrastructureError, Result};
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::{AccountRepository, SecretRepository};

use std::default::Default;

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
    G: Serialize + DeserializeOwned + Eq + Clone + 'static,
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

    async fn delete_secret(&self, id: &Uuid) -> Result<Option<Secret>> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(&self.scope_settings.table_names.credentials, *id);
        let result: Option<Secret> = self.db.delete(record_id).await.map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Delete,
                message: format!("Failed to delete and return secret: {}", e),
                table: Some(self.scope_settings.table_names.credentials.clone()),
                record_id: Some(id.to_string()),
            })
        })?;
        Ok(result)
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
        use subtle::Choice;

        self.use_ns_db().await?;
        let record_id =
            RecordId::from_table_key(&self.scope_settings.table_names.credentials, credentials.id);

        // Step 1: Check if user exists by querying the secret
        let exists_query = "SELECT VALUE secret FROM only $record_id".to_string();
        let mut exists_response = self
            .db
            .query(exists_query)
            .bind(("record_id", record_id))
            .await
            .map_err(|e| {
                Error::Infrastructure(InfrastructureError::Database {
                    operation: DatabaseOperation::Query,
                    message: format!("Failed to check user existence: {}", e),
                    table: Some(self.scope_settings.table_names.credentials.clone()),
                    record_id: None,
                })
            })?;

        let stored_secret: Option<String> = exists_response.take(0).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Query,
                message: format!("Failed to extract secret: {}", e),
                table: Some(self.scope_settings.table_names.credentials.clone()),
                record_id: None,
            })
        })?;

        // Step 2: Determine user existence and prepare hash for verification
        let (hash_for_verification, user_exists_choice) = match stored_secret {
            Some(secret) => (secret, Choice::from(1u8)),
            None => {
                // Use a realistic dummy Argon2 hash for constant-time operation
                let dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3ODkwYWJjZGVmZ2hpams$+U4VpzOTOuH3Lz3dN2CX2z6VZhUZP1c1xN1y2Z3Z4aA".to_string();
                (dummy_hash, Choice::from(0u8))
            }
        };

        // Step 3: ALWAYS perform Argon2 verification (constant time)
        let verify_query =
            "crypto::argon2::compare(type::string($stored_hash), type::string($request_secret))"
                .to_string();
        let mut verify_response = self
            .db
            .query(verify_query)
            .bind(("stored_hash", hash_for_verification))
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

        let hash_matches: Option<bool> = verify_response.take(0).map_err(|e| {
            Error::Infrastructure(InfrastructureError::Database {
                operation: DatabaseOperation::Query,
                message: format!("Failed to extract verification result: {}", e),
                table: Some(self.scope_settings.table_names.credentials.clone()),
                record_id: None,
            })
        })?;

        // Step 4: Combine results using constant-time operations
        let hash_matches_choice = Choice::from(if hash_matches.unwrap_or(false) {
            1u8
        } else {
            0u8
        });
        let final_success_choice = user_exists_choice & hash_matches_choice;

        // Step 5: Convert back to VerificationResult
        let final_result = if bool::from(final_success_choice) {
            VerificationResult::Ok
        } else {
            VerificationResult::Unauthorized
        };

        Ok(final_result)
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

        let creds = Secret::new(&id, "admin_password", Argon2Hasher::default()).unwrap();

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
        use crate::prelude::{Account, Group, Role};
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
