//! Memory storage implementations.

use crate::hashing::{Argon2Hasher, VerificationResult};
use crate::secrets::Secret;
use crate::services::{AccountStorageService, SecretStorageService, SecretVerifierService};
use crate::utils::AccessHierarchy;
use crate::{Account, Error};

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
pub struct MemorySecretStorage {
    store: Arc<RwLock<HashMap<Uuid, String>>>,
}

impl Default for MemorySecretStorage {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl TryFrom<Vec<Secret>> for MemorySecretStorage {
    type Error = Error;
    fn try_from(value: Vec<Secret>) -> Result<Self, Error> {
        let mut store = HashMap::with_capacity(value.len());
        value.into_iter().for_each(|v| {
            store.insert(v.account_id.clone(), v.secret);
        });
        let store = Arc::new(RwLock::new(store));
        Ok(Self { store })
    }
}

impl SecretStorageService for MemorySecretStorage {
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&secret.account_id)
        };

        if already_present {
            return Err(anyhow!(Error::SecretStorage(
                "AccountID is already present.".to_string()
            )));
        }

        let mut write = self.store.write().await;
        debug!("Got write lock on secret storage.");

        if write.insert(secret.account_id, secret.secret).is_some() {
            return Err(anyhow!(Error::SecretStorage("This should never occur because it is checked if the key is already present a few lines earlier.".to_string())));
        };
        Ok(true)
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        let mut write = self.store.write().await;
        Ok(write.remove(id).is_some())
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        let mut write = self.store.write().await;
        write.insert(secret.account_id, secret.secret);
        Ok(())
    }
}

impl SecretVerifierService for MemorySecretStorage {
    async fn verify_secret(&self, secret: Secret) -> Result<VerificationResult> {
        let read = self.store.read().await;
        let Some(stored_secret) = read.get(&secret.account_id) else {
            return Ok(VerificationResult::Unauthorized);
        };
        secret.verify(stored_secret, Argon2Hasher)
    }
}

#[test]
fn credentials_memory_storage() {
    tokio_test::block_on(async move {
        let id = Uuid::now_v7();
        let creds = Secret::new(&id, "admin_password", Argon2Hasher).unwrap();
        let creds_to_verify = Secret::new(&id, "admin_password", Argon2Hasher).unwrap();
        let wrong_creds = Secret::new(&id, "admin_passwordwrong", Argon2Hasher).unwrap();

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
