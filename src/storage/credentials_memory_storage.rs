use crate::Error;
use crate::credentials::{Credentials, CredentialsStorageService, CredentialsVerifierService};
use crate::secrets::SecretsHashingService;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Stores credentials in memory for authentication.
///
/// For simplicity, this storage does implement both [CredentialsStorageService] as well as [CredentialsVerifierService].
/// # Create and use a credential storage for authentication
/// ```rust
/// # tokio_test::block_on(async move {
/// # use axum_gate::credentials::{Credentials, CredentialsVerifierService};
/// # use axum_gate::secrets::Argon2Hasher;
/// # use axum_gate::storage::CredentialsMemoryStorage;
/// let hasher = Argon2Hasher::default();
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let creds = Credentials::new("admin@example.com", "admin_password".as_bytes())
///     .hash_secret(&hasher)
///     .unwrap();
/// let creds_to_verify = Credentials::new("admin@example.com", "admin_password".as_bytes().to_vec());
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let creds_storage = CredentialsMemoryStorage::from(vec![creds.clone()]);
/// assert_eq!(true, creds_storage.verify_credentials(&creds_to_verify, &hasher).await.unwrap());
/// let false_creds = Credentials::new("admin@example.com", "crazysecret".as_bytes())
///     .hash_secret(&hasher).unwrap();
/// assert_eq!(false, creds_storage.verify_credentials(&false_creds, &hasher).await.unwrap());
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
        hasher.verify_secret(&credentials.secret, &stored_secret)
    }
}

#[test]
fn credentials_memory_storage() {
    tokio_test::block_on(async move {
        use crate::secrets::Argon2Hasher;

        let hasher = Argon2Hasher::default();
        let creds = Credentials::new(
            "admin@example.com".to_string(),
            "admin_password".to_string().as_bytes().to_vec(),
        )
        .hash_secret(&hasher)
        .unwrap();
        let creds_to_verify = Credentials::new(
            "admin@example.com".to_string(),
            "admin_password".to_string().as_bytes().to_vec(),
        );
        let wrong_creds = Credentials::new(
            "admin@example.com".to_string(),
            "admin_passwordwrong".to_string().as_bytes().to_vec(),
        );

        let creds_storage = CredentialsMemoryStorage::from(vec![creds.clone()]);
        assert_eq!(
            false,
            creds_storage
                .verify_credentials(&wrong_creds, &hasher)
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            creds_storage
                .verify_credentials(&creds_to_verify, &hasher)
                .await
                .unwrap()
        );
    })
}
