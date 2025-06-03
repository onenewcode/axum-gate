//! Memory storage implementations.

use crate::Account;
use crate::Error;
use crate::credentials::Credentials;
use crate::secrets::Argon2Hasher;
use crate::services::{AccountStorageService, SecretStorageService, SecretsHashingService};
use crate::utils::AccessHierarchy;

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::RwLock;
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

impl<R, G> From<Vec<Account<R, G>>> for MemoryAccountStorage<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    fn from(value: Vec<Account<R, G>>) -> Self {
        let mut accounts = HashMap::new();
        for val in value {
            let id = val.id().clone();
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
    async fn query_by_username(&self, username: &str) -> Result<Option<Account<R, G>>> {
        let read = self.accounts.read().await;
        Ok(read.get(username).cloned())
    }
    async fn store(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let id = account.username.clone();
        let mut write = self.accounts.write().await;
        write.insert(id, account.clone());
        Ok(Some(account))
    }
    async fn delete(&self, account_id: &str) -> Result<Option<Account<R, G>>> {
        let mut write = self.accounts.write().await;
        if !write.contains_key(account_id) {
            return Ok(None);
        }
        Ok(write.remove(account_id))
    }
    async fn update(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        self.store(account).await
    }
}
/// Stores secrets in memory for authentication.
///
/// # Create and use a credential storage for authentication
/// ```rust
/// # tokio_test::block_on(async move {
/// # use axum_gate::credentials::{Credentials, CredentialsVerifierService};
/// # use axum_gate::storage::memory::MemorySecretStorage;
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let creds = Credentials::new(&"admin@example.com", "admin_password");
/// let creds_to_verify = Credentials::new(&"admin@example.com", "admin_password");
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let creds_storage = MemorySecretStorage::try_from(vec![creds.clone()]).unwrap();
/// assert_eq!(true, creds_storage.verify_credentials(&creds_to_verify).await.unwrap());
/// let false_creds = Credentials::new(&"admin@example.com", "crazysecret");
/// assert_eq!(false, creds_storage.verify_credentials(&false_creds).await.unwrap());
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
            hasher: Argon2Hasher::default(),
        }
    }
}

impl TryFrom<Vec<Credentials<Uuid>>> for MemorySecretStorage<Argon2Hasher> {
    type Error = Error;
    fn try_from(value: Vec<Credentials<Uuid>>) -> Result<Self, Error> {
        let hasher = Argon2Hasher::default();
        let mut store = HashMap::with_capacity(value.len());
        let mut value_iter = value.into_iter();
        while let Some(v) = value_iter.next() {
            let secret = hasher
                .hash_secret(&v.secret)
                .map_err(|e| Error::SecretStorage(e.to_string()))?;

            store.insert(v.id, secret);
        }
        let store = Arc::new(RwLock::new(store));
        Ok(Self {
            store,
            hasher: Argon2Hasher::default(),
        })
    }
}

impl<Hasher> SecretStorageService for MemorySecretStorage<Hasher>
where
    Hasher: SecretsHashingService,
{
    async fn store(&self, credentials: Credentials<Uuid>) -> Result<bool> {
        let mut write = self.store.write().await;

        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&credentials.id)
        };

        if already_present {
            return Err(anyhow!(Error::SecretStorage(format!(
                "Credentials ID is already present."
            ))));
        }

        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;

        if write
            .insert(credentials.id.clone(), secret.clone())
            .is_none()
        {
            return Err(anyhow!(Error::SecretStorage(format!(
                "This should never occur because it is checked if the key is already present a few lines earlier."
            ))));
        };
        Ok(true)
    }

    async fn delete(&self, id: &Uuid) -> Result<bool> {
        let mut write = self.store.write().await;
        Ok(write.remove(id).is_some())
    }

    async fn update(&self, credentials: Credentials<Uuid>) -> Result<()> {
        let mut write = self.store.write().await;
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::SecretStorage(e.to_string()))?;
        write.insert(credentials.id, secret);
        Ok(())
    }

    async fn verify(&self, credentials: Credentials<Uuid>) -> Result<bool> {
        let read = self.store.read().await;
        let Some(stored_secret) = read.get(&credentials.id) else {
            return Ok(false);
        };
        self.hasher
            .verify_secret(&credentials.secret, stored_secret)
    }
}

#[test]
fn credentials_memory_storage() {
    tokio_test::block_on(async move {
        let creds = Credentials::new(&"admin@example.com", "admin_password");
        let creds_to_verify = Credentials::new(&"admin@example.com", "admin_password");
        let wrong_creds = Credentials::new(&"admin@example.com", "admin_passwordwrong");

        let creds_storage = MemorySecretStorage::try_from(vec![creds.clone()]).unwrap();
        assert_eq!(
            false,
            creds_storage
                .verify_credentials(&wrong_creds)
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            creds_storage
                .verify_credentials(&creds_to_verify)
                .await
                .unwrap()
        );
    })
}
