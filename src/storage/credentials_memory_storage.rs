use crate::Error;
use crate::services::CredentialsVerifierService;
use crate::{
    credentials::Credentials,
    services::{CredentialsStorageService, SecretsHashingService},
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stores credentials in memory for authentication.
///
/// For simplicity, this storage does implement both [CredentialsStorageService] as well as [CredentialsVerifierService].
/// # Create and use a credential storage for authentication
/// ```rust
/// # use axum_gate::credentials::Credentials<Id, Secret>;
/// # use axum_gate::credentials::Credentials<Id, Secret>;
/// # use axum_gate::storage::CredentialsMemoryStorage;
/// # use axum_gate::services::CredentialsVerifierService;
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let creds = Credentials<Id, Secret>::new("admin@example.com", "admin_password");
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let hashed_creds = Credentials<Id, Secret>::new_argon2(&creds.id, &creds.secret).unwrap();
/// let creds_storage = CredentialsMemoryStorage::from(vec![hashed_creds.clone()]);
/// # let creds_storage_1 = creds_storage.clone();
/// # tokio_test::block_on(async move {
/// # let creds_storage = creds_storage_1;
/// assert_eq!(true, creds_storage.verify_credentials(&hashed_creds).await.unwrap());
/// # });
/// let hashed_creds = Credentials<Id, Secret>::new_argon2(&"admin@example.com", &"crazysecret").unwrap();
/// # tokio_test::block_on(async move {
/// assert_eq!(false, creds_storage.verify_credentials(&hashed_creds).await.unwrap());
/// # });
/// ```
#[derive(Clone)]
pub struct CredentialsMemoryStorage<Id, Secret>
where
    Id: Hash,
{
    store: Arc<RwLock<HashMap<Id, Secret>>>,
}

impl<Id, Secret> Default for CredentialsMemoryStorage<Id, Secret>
where
    Id: Hash,
{
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<Id, Secret> From<Vec<Credentials<Id, Secret>>> for CredentialsMemoryStorage<Id, Secret>
where
    Id: Hash + Eq,
{
    fn from(value: Vec<Credentials<Id, Secret>>) -> Self {
        let mut store = HashMap::with_capacity(value.len());
        let mut value_iter = value.into_iter();
        while let Some(v) = value_iter.next() {
            store.insert(v.id, v.secret);
        }
        let store = Arc::new(RwLock::new(store));
        Self { store }
    }
}

impl<Id, Secret> CredentialsStorageService<Id, Secret> for CredentialsMemoryStorage<Id, Secret>
where
    Id: Hash + Eq + Clone,
{
    async fn store_credentials(
        &self,
        credentials: Credentials<Id, Secret>,
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
        credentials: Credentials<Id, Secret>,
    ) -> Result<bool, crate::Error> {
        let mut write = self.store.write().await;
        Ok(write.remove(&credentials.id).is_some())
    }

    async fn update_credentials(
        &self,
        credentials: Credentials<Id, Secret>,
    ) -> Result<(), crate::Error> {
        let mut write = self.store.write().await;
        write.insert(credentials.id.clone(), credentials.secret);
        Ok(())
    }
}

impl<Id> CredentialsVerifierService<Id, Vec<u8>> for CredentialsMemoryStorage<Id, Vec<u8>>
where
    Id: Hash + Eq,
{
    async fn verify_credentials<Hasher>(
        &self,
        credentials: &Credentials<Id, Vec<u8>>,
        hasher: &Hasher,
    ) -> Result<bool, Error>
    where
        Hasher: SecretsHashingService,
    {
        let read = self.store.read().await;
        let Some(stored_secret) = read.get(&credentials.id) else {
            return Ok(false);
        };
        Ok(hasher
            .verify_secret(&credentials.secret, &stored_secret)
            .is_ok())
    }
}
