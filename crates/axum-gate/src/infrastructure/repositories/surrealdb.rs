//! Repository implementations that use surrealdb as backend.
//!
//! This module provides repository implementations backed by SurrealDB.
//! It includes constant‑time credential verification logic that mitigates
//! timing side channels (user enumeration) by always performing an Argon2
//! verification – even when the user/secret does not exist – using a
//! precomputed dummy hash whose parameters match the build's active
//! Argon2 configuration (via `Argon2Hasher::default()`).

use super::TableNames;
use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::{Secret, VerificationResult};
use crate::errors::{Error, InfrastructureError, Result};
use crate::infrastructure::errors::DatabaseOperation;
use crate::infrastructure::hashing::Argon2Hasher;
use crate::ports::auth::{CredentialsVerifier, HashingService};
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
///
/// Constant‑time credential verification notes:
/// - A dummy Argon2 hash is precomputed once (construction) using the same
///   Argon2 preset as normal secrets (build‑mode dependent).
/// - Nonexistent user credential checks verify against this dummy hash so the
///   timing is aligned with real user verification.
#[derive(Clone)]
pub struct SurrealDbRepository<S>
where
    S: Connection,
{
    db: Surreal<S>,
    scope_settings: DatabaseScope,
    /// Precomputed dummy Argon2 hash used when a user's secret does not exist.
    /// Ensures the Argon2 verification path is always exercised.
    dummy_hash: String,
}

impl<S> SurrealDbRepository<S>
where
    S: Connection,
{
    /// Creates a new repository that uses the given database connection limited by the given scope.
    pub fn new(db: Surreal<S>, scope_settings: DatabaseScope) -> Self {
        let hasher = Argon2Hasher::default();
        // Panic on failure here is acceptable: construction failure indicates a
        // fundamental issue (e.g. RNG) and mirrors the in‑memory repo strategy.
        let dummy_hash = hasher
            .hash_value("dummy_password")
            .expect("Failed to generate dummy Argon2 hash for SurrealDbRepository");
        Self {
            db,
            scope_settings,
            dummy_hash,
        }
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

        // Step 1: Query stored secret (if any)
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

        // Step 2: Select hash to verify against (always perform verification)
        let (hash_for_verification, user_exists_choice) = match stored_secret {
            Some(secret) => (secret, Choice::from(1u8)),
            None => (self.dummy_hash.clone(), Choice::from(0u8)),
        };

        // Step 3: Perform Argon2 verification inside the database engine (SurrealDB function)
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

        // Step 4: Constant-time combination: success only if user exists AND hash matches
        let hash_matches_choice = Choice::from(if hash_matches.unwrap_or(false) {
            1u8
        } else {
            0u8
        });
        let final_success_choice = user_exists_choice & hash_matches_choice;

        // Step 5: Convert to domain result
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
        let db = Surreal::new::<Mem>(()).await.unwrap();
        let scope = DatabaseScope::default();
        let repo = SurrealDbRepository::new(db, scope);

        repo.use_ns_db().await.unwrap();

        // create a secret
        let hasher = Argon2Hasher::default();
        let secret = Secret::new(&Uuid::now_v7(), "my_secret", hasher).unwrap();

        // store it
        assert!(repo.store_secret(secret.clone()).await.unwrap());

        // update it
        let mut secret_new = secret.clone();
        secret_new.secret = secret.secret.clone();
        repo.update_secret(secret_new.clone()).await.unwrap();

        // verify it
        let credentials = Credentials::new(&secret.account_id, "my_secret");
        assert!(matches!(
            repo.verify_credentials(credentials).await,
            Ok(VerificationResult::Ok)
        ));
    });
}
