use crate::services::CredentialsVerifierService;
use crate::{
    credentials::{Credentials, HashedCredentials},
    services::CredentialsStorageService,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stores credentials in memory for authentication.
///
/// For simplicity, this storage does implement both [CredentialsStorageService] as well as [CredentialsVerifierService].
/// # Create and use a credential storage for authentication
/// ```rust
/// # use axum_gate::credentials::Credentials;
/// # use axum_gate::credentials::HashedCredentials;
/// # use axum_gate::storage::CredentialsMemoryStorage;
/// # use axum_gate::services::CredentialsVerifierService;
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let creds = Credentials::new("admin@example.com", "admin_password");
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let hashed_creds = HashedCredentials::new_argon2(&creds.id, &creds.secret).unwrap();
/// let creds_storage = CredentialsMemoryStorage::from(vec![hashed_creds.clone()]);
/// # let creds_storage_1 = creds_storage.clone();
/// # tokio_test::block_on(async move {
/// # let creds_storage = creds_storage_1;
/// assert_eq!(true, creds_storage.verify_credentials(&hashed_creds).await.unwrap());
/// # });
/// let hashed_creds = HashedCredentials::new_argon2(&"admin@example.com", &"crazysecret").unwrap();
/// # tokio_test::block_on(async move {
/// assert_eq!(false, creds_storage.verify_credentials(&hashed_creds).await.unwrap());
/// # });
/// ```
#[derive(Clone)]
pub struct CredentialsMemoryStorage {
    store: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl Default for CredentialsMemoryStorage {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl From<Vec<HashedCredentials>> for CredentialsMemoryStorage {
    fn from(value: Vec<HashedCredentials>) -> Self {
        let mut store = HashMap::with_capacity(value.len());
        let mut value_iter = value.into_iter();
        while let Some(v) = value_iter.next() {
            store.insert(v.id, v.secret);
        }
        let store = Arc::new(RwLock::new(store));
        Self { store }
    }
}

impl CredentialsStorageService for CredentialsMemoryStorage {
    async fn store_credentials(
        &self,
        credentials: HashedCredentials,
    ) -> Result<bool, crate::Error> {
        let mut write = self.store.write().await;

        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&credentials.id)
        };

        if already_present {
            return Ok(false);
        }

        Ok(write
            .insert(credentials.id.clone(), credentials.secret)
            .is_none())
    }

    async fn remove_credentials(
        &self,
        credentials: HashedCredentials,
    ) -> Result<bool, crate::Error> {
        let mut write = self.store.write().await;
        Ok(write.remove(&credentials.id).is_some())
    }

    async fn update_credentials(&self, credentials: HashedCredentials) -> Result<(), crate::Error> {
        let mut write = self.store.write().await;
        write.insert(credentials.id.clone(), credentials.secret);
        Ok(())
    }
}

impl CredentialsVerifierService for CredentialsMemoryStorage {
    async fn verify_credentials<Id, Secret, Hasher>(
        &self,
        credentials: &Credentials<Id, Secret>,
        hasher: Hasher,
    ) -> Result<bool, crate::Error>
    where
        Id: std::hash::Hash + Eq,
        Secret: std::hash::Hash + Eq,
    {
        let read = self.store.read().await;
        Ok(read
            .get(&credentials.id)
            .map(|secret| credentials.secret == *secret)
            .unwrap_or(false))
    }
}
