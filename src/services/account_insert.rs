use crate::{
    Account, Credentials, Error,
    services::{AccountStorageService, SecretStorageService},
    utils::AccessHierarchy,
};

use std::sync::Arc;

use anyhow::{Result, anyhow};

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
        let account = Account::new(&self.user_id, &self.roles, &self.groups);
        let Some(account) = account_storage.store(account).await? else {
            return Err(anyhow!(Error::AccountStorage(format!(
                "Account storage returned None on insertion."
            ))));
        };
        let id = &account.account_id;
        let cred = Credentials::new(id, &self.secret);
        if !secret_storage.store(cred).await? {
            Err(anyhow!(Error::SecretStorage(format!(
                "Storing secret in storage returned false."
            ))))
        } else {
            Ok(Some(account))
        }
    }
}
