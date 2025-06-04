//! Memory storage implementations.

use crate::Account;
use crate::Error;
use crate::credentials::Credentials;
use crate::secrets::Argon2Hasher;
use crate::secrets::VerificationResult;
use crate::services::{AccountStorageService, SecretStorageService, SecretsHashingService};
use crate::utils::AccessHierarchy;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

/// A [MemoryAccountStorage] is a data structure where all [Account]s are stored in memory.
#[derive(Clone)]
pub struct MemoryAccountStorage<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    accounts: Arc<RwLock<HashMap<String, Account<R, G>>>>,
}

impl<R, G> Default for MemoryAccountStorage<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    fn default() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<R, G> From<Vec<Account<R, G>>> for MemoryAccountStorage<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    fn from(value: Vec<Account<R, G>>) -> Self {
        let mut accounts = HashMap::new();
        for val in value {
            let id = val.user_id.clone();
            accounts.insert(id, val);
        }
        let accounts = Arc::new(RwLock::new(accounts));
        Self { accounts }
    }
}

impl<R, G> AccountStorageService<R, G> for MemoryAccountStorage<R, G>
where
    Account<R, G>: Clone,
    R: AccessHierarchy + Eq,
    G: Eq,
{
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let read = self.accounts.read().await;
        Ok(read.get(user_id).cloned())
    }
    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let id = account.user_id.clone();
        let mut write = self.accounts.write().await;
        write.insert(id, account.clone());
        Ok(Some(account))
    }
    async fn delete_account(&self, account_id: &str) -> Result<Option<Account<R, G>>> {
        let mut write = self.accounts.write().await;
        if !write.contains_key(account_id) {
            return Ok(None);
        }
        Ok(write.remove(account_id))
    }
    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        self.store_account(account).await
    }
}
/// Stores secrets in memory for authentication.
///
/// # Create and use a credential storage for authentication
/// ```rust
/// # tokio_test::block_on(async move {
/// # use axum_gate::Credentials;
/// # use axum_gate::secrets::VerificationResult;
/// # use axum_gate::services::SecretStorageService;
/// # use axum_gate::storage::memory::MemorySecretStorage;
/// # use uuid::Uuid;
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let id = Uuid::now_v7();
/// let creds = Credentials::new(&id, "admin_password");
/// let creds_to_verify = Credentials::new(&id, "admin_password");
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let creds_storage = MemorySecretStorage::try_from(vec![creds.clone()]).unwrap();
/// assert_eq!(VerificationResult::Ok, creds_storage.verify(creds_to_verify).await.unwrap());
/// let false_creds = Credentials::new(&id, "crazysecret");
/// assert_eq!(VerificationResult::Unauthorized, creds_storage.verify(false_creds).await.unwrap());
/// # });
/// ```
#[derive(Clone)]
pub struct MemorySecretStorage<Hasher>
where
    Hasher: SecretsHashingService,
{
    store: Arc<RwLock<HashMap<Uuid, String>>>,
    hasher: Hasher,
}

impl Default for MemorySecretStorage<Argon2Hasher> {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            hasher: Argon2Hasher,
        }
    }
}

impl TryFrom<Vec<Credentials<Uuid>>> for MemorySecretStorage<Argon2Hasher> {
    type Error = Error;
    fn try_from(value: Vec<Credentials<Uuid>>) -> Result<Self, Error> {
        let hasher = Argon2Hasher;
        let mut store = HashMap::with_capacity(value.len());
        let value_iter = value.into_iter();
        for v in value_iter {
            let secret = hasher
                .hash_secret(&v.secret)
                .map_err(|e| Error::SecretStorage(e.to_string()))?;

            store.insert(v.user_id, secret);
        }
        let store = Arc::new(RwLock::new(store));
        Ok(Self {
            store,
            hasher: Argon2Hasher,
        })
    }
}

impl<Hasher> SecretStorageService for MemorySecretStorage<Hasher>
where
    Hasher: SecretsHashingService,
{
    async fn store_secret(&self, credentials: Credentials<Uuid>) -> Result<bool> {
        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&credentials.user_id)
        };

        if already_present {
            return Err(anyhow!(Error::SecretStorage(
                "Credentials ID is already present.".to_string()
            )));
        }

        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        debug!("Sucessfully hashed secret.");

        let mut write = self.store.write().await;
        debug!("Got write lock on secret storage.");

        if write.insert(credentials.user_id, secret.clone()).is_some() {
            return Err(anyhow!(Error::SecretStorage("This should never occur because it is checked if the key is already present a few lines earlier.".to_string())));
        };
        Ok(true)
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        let mut write = self.store.write().await;
        Ok(write.remove(id).is_some())
    }

    async fn update_secret(&self, credentials: Credentials<Uuid>) -> Result<()> {
        let mut write = self.store.write().await;
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        write.insert(credentials.user_id, secret);
        Ok(())
    }

    async fn verify_secret(&self, credentials: Credentials<Uuid>) -> Result<VerificationResult> {
        let read = self.store.read().await;
        let Some(stored_secret) = read.get(&credentials.user_id) else {
            return Ok(VerificationResult::Unauthorized);
        };
        self.hasher
            .verify_secret(&credentials.secret, stored_secret)
    }
}

#[test]
fn credentials_memory_storage() {
    tokio_test::block_on(async move {
        let id = Uuid::now_v7();
        let creds = Credentials::new(&id, "admin_password");
        let creds_to_verify = Credentials::new(&id, "admin_password");
        let wrong_creds = Credentials::new(&id, "admin_passwordwrong");

        let creds_storage = MemorySecretStorage::try_from(vec![creds.clone()]).unwrap();
        assert_eq!(
            VerificationResult::Unauthorized,
            creds_storage.verify_secret(wrong_creds).await.unwrap()
        );
        assert_eq!(
            VerificationResult::Ok,
            creds_storage.verify_secret(creds_to_verify).await.unwrap()
        );
    })
}
