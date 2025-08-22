use crate::domain::traits::AccessHierarchy;
use crate::infrastructure::services::{AccountStorageService, SecretStorageService};
use crate::{Account, Error};

use std::sync::Arc;

use anyhow::{Result, anyhow};

/// Removes the given account and its corresponding secret from storages.
pub struct AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    account: Account<R, G>,
}

impl<R, G> AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Creates a new instance with the account that should be deleted.
    pub fn delete(account: Account<R, G>) -> Self {
        Self { account }
    }

    /// Removes the account and its secret from the given storages.
    pub async fn from_storages<AccStore, SecStore>(
        self,
        account_storage: Arc<AccStore>,
        secret_storage: Arc<SecStore>,
    ) -> Result<()>
    where
        AccStore: AccountStorageService<R, G>,
        SecStore: SecretStorageService,
    {
        if !secret_storage
            .delete_secret(&self.account.account_id)
            .await?
        {
            return Err(anyhow!(Error::SecretStorage(
                "Deleting secret in storage returned false.".to_string()
            )));
        };

        if account_storage
            .delete_account(&self.account.user_id)
            .await?
            .is_none()
        {
            return Err(anyhow!(Error::AccountStorage(
                "Account storage returned None on insertion.".to_string()
            )));
        };
        Ok(())
    }
}
