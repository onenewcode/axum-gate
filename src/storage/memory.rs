//! Memory storage implementations.

use crate::Error;
use crate::credentials::{Credentials, CredentialsVerifierService};
use crate::passport::Passport;
use crate::secrets::{Argon2Hasher, SecretsHashingService};
use crate::storage::CredentialsStorageService;
use crate::storage::PassportStorageService;

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use tokio::sync::RwLock;

/// A [MemoryPassportStorage] is a data structure where all [Passport]s are stored in memory.
#[derive(Clone)]
pub struct MemoryPassportStorage<P>
where
    P: Passport + Clone,
{
    passports: Arc<RwLock<HashMap<P::Id, P>>>,
}

impl<P> From<Vec<P>> for MemoryPassportStorage<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash + Clone,
{
    fn from(value: Vec<P>) -> Self {
        let mut passports = HashMap::new();
        for val in value {
            let id = val.id().clone();
            passports.insert(id, val);
        }
        let passports = Arc::new(RwLock::new(passports));
        Self { passports }
    }
}

impl<P> PassportStorageService<P> for MemoryPassportStorage<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash + Clone,
{
    async fn passport(&self, passport_id: &P::Id) -> Result<Option<P>, Error> {
        let read = self.passports.read().await;
        Ok(read.get(passport_id).cloned())
    }
    async fn store_passport(&self, passport: &P) -> Result<Option<P::Id>, Error> {
        let id = passport.id().clone();
        let mut write = self.passports.write().await;
        write.insert(id.clone(), passport.clone());
        Ok(Some(id))
    }
    async fn remove_passport(&self, passport_id: &P::Id) -> Result<Option<P>, Error> {
        let mut write = self.passports.write().await;
        if !write.contains_key(passport_id) {
            return Ok(None);
        }
        Ok(write.remove(passport_id))
    }
}
/// Stores credentials in memory for authentication.
///
/// For simplicity, this storage does implement both [CredentialsStorageService] as well as [CredentialsVerifierService].
/// # Create and use a credential storage for authentication
/// ```rust
/// # tokio_test::block_on(async move {
/// # use axum_gate::credentials::{Credentials, CredentialsVerifierService};
/// # use axum_gate::storage::memory::MemoryCredentialsStorage;
/// // Lets assume the user id is an email address and the user has a gooood password.
/// let creds = Credentials::new(&"admin@example.com", "admin_password");
/// let creds_to_verify = Credentials::new(&"admin@example.com", "admin_password");
/// // In order to enable user verification we need to store a hashed version in our pre-defined
/// // memory storage.
/// let creds_storage = MemoryCredentialsStorage::try_from(vec![creds.clone()]).unwrap();
/// assert_eq!(true, creds_storage.verify_credentials(&creds_to_verify).await.unwrap());
/// let false_creds = Credentials::new(&"admin@example.com", "crazysecret");
/// assert_eq!(false, creds_storage.verify_credentials(&false_creds).await.unwrap());
/// # });
/// ```
#[derive(Clone)]
pub struct MemoryCredentialsStorage<Id, Hasher>
where
    Id: Hash,
    Hasher: SecretsHashingService,
{
    store: Arc<RwLock<HashMap<Id, String>>>,
    hasher: Hasher,
}

impl<Id> Default for MemoryCredentialsStorage<Id, Argon2Hasher>
where
    Id: Hash,
{
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            hasher: Argon2Hasher::default(),
        }
    }
}

impl<Id> TryFrom<Vec<Credentials<Id>>> for MemoryCredentialsStorage<Id, Argon2Hasher>
where
    Id: Hash + Eq,
{
    type Error = Error;
    fn try_from(value: Vec<Credentials<Id>>) -> Result<Self, Error> {
        let hasher = Argon2Hasher::default();
        let mut store = HashMap::with_capacity(value.len());
        let mut value_iter = value.into_iter();
        while let Some(v) = value_iter.next() {
            let secret = hasher
                .hash_secret(&v.secret)
                .map_err(|e| Error::CredentialsStorage(e.to_string()))?;

            store.insert(v.id, secret);
        }
        let store = Arc::new(RwLock::new(store));
        Ok(Self {
            store,
            hasher: Argon2Hasher::default(),
        })
    }
}

impl<Id, Hasher> CredentialsStorageService<Id> for MemoryCredentialsStorage<Id, Hasher>
where
    Id: Hash + Eq + Clone,
    Hasher: SecretsHashingService,
{
    async fn store_credentials(
        &self,
        credentials: Credentials<Id>,
    ) -> Result<Credentials<Id>, crate::Error> {
        let mut write = self.store.write().await;

        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&credentials.id)
        };

        if already_present {
            return Err(Error::CredentialsStorage(format!(
                "Credentials ID is already present."
            )));
        }

        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;

        if write
            .insert(credentials.id.clone(), secret.clone())
            .is_none()
        {
            return Err(Error::CredentialsStorage(format!(
                "This should never occur because it is checked if the key is already present a few lines earlier."
            )));
        };
        Ok(Credentials::new(&credentials.id, &secret))
    }

    async fn remove_credentials(&self, id: &Id) -> Result<bool, crate::Error> {
        let mut write = self.store.write().await;
        Ok(write.remove(id).is_some())
    }

    async fn update_credentials(&self, credentials: Credentials<Id>) -> Result<(), crate::Error> {
        let mut write = self.store.write().await;
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        write.insert(credentials.id, secret);
        Ok(())
    }
}

impl<Id, Hasher> CredentialsVerifierService<Id> for MemoryCredentialsStorage<Id, Hasher>
where
    Id: Hash + Eq,
    Hasher: SecretsHashingService,
{
    async fn verify_credentials(&self, credentials: &Credentials<Id>) -> Result<bool, Error>
    where
        Hasher: SecretsHashingService,
    {
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

        let creds_storage = MemoryCredentialsStorage::try_from(vec![creds.clone()]).unwrap();
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
