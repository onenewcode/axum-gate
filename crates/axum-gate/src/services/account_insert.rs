use crate::{
    Account, Error,
    hashing::Argon2Hasher,
    secrets::Secret,
    services::{AccountStorageService, SecretStorageService},
    utils::AccessHierarchy,
};

use std::sync::Arc;

use anyhow::{Result, anyhow};
use roaring::RoaringBitmap;
use tracing::debug;

/// Ergonomic service that is able to insert/register a new [Account] to the storages.
pub struct AccountInsertService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    user_id: String,
    secret: String,
    roles: Vec<R>,
    groups: Vec<G>,
    permissions: RoaringBitmap,
}

impl<R, G> AccountInsertService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a new instance that will insert an [Account] with the given details.
    pub fn insert(user_id: &str, secret: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            secret: secret.to_string(),
            roles: vec![],
            groups: vec![],
            permissions: RoaringBitmap::new(),
        }
    }

    /// Adds the given roles to the [Account] that will be inserted.
    pub fn with_roles(self, roles: Vec<R>) -> Self {
        Self { roles, ..self }
    }

    /// Adds the given groups to the [Account] that will be inserted.
    pub fn with_groups(self, groups: Vec<G>) -> Self {
        Self { groups, ..self }
    }

    /// Adds the given permission list to the [Account].
    pub fn with_permissions<P: Into<u32>>(self, permissions: Vec<P>) -> Self {
        let permissions = RoaringBitmap::from_iter(permissions.into_iter().map(|p| p.into()));
        Self {
            permissions,
            ..self
        }
    }

    /// Adds the given permission bitmap directly to the [Account].
    ///
    /// This method is useful when using the new zero-synchronization permission system
    /// where permissions are managed as bitmaps directly.
    pub fn with_permissions_bitmap(self, permissions: RoaringBitmap) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Adds the created [Account] to the storages.
    pub async fn into_storages<AccStore, SecStore>(
        self,
        account_storage: Arc<AccStore>,
        secret_storage: Arc<SecStore>,
    ) -> Result<Option<Account<R, G>>>
    where
        AccStore: AccountStorageService<R, G>,
        SecStore: SecretStorageService,
    {
        let account = Account::new(&self.user_id, &self.roles, &self.groups)
            .with_permissions(self.permissions);
        debug!("Created account.");
        let Some(account) = account_storage.store_account(account).await? else {
            return Err(anyhow!(Error::AccountStorage(
                "Account storage returned None on insertion.".to_string()
            )));
        };
        debug!("Stored account in account storage.");
        let id = &account.account_id;
        let secret = Secret::new(id, &self.secret, Argon2Hasher)?;
        if !secret_storage.store_secret(secret).await? {
            Err(anyhow!(Error::SecretStorage(
                "Storing secret in storage returned false.".to_string()
            )))
        } else {
            debug!("Stored secret in secret storage.");
            Ok(Some(account))
        }
    }
}
