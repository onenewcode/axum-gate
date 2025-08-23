use crate::domain::traits::AccessHierarchy;
use crate::infrastructure::services::SecretRepositoryService;
use crate::ports::repositories::AccountRepository;
use crate::{Account, Error};

use std::sync::Arc;

use anyhow::{Result, anyhow};

/// Removes the given account and its corresponding secret from repositories.
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

    /// Removes the account and its secret from the given repositories.
    pub async fn from_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> Result<()>
    where
        AccRepo: AccountRepository<R, G>,
        SecRepo: SecretRepositoryService,
    {
        if !secret_repository
            .delete_secret(&self.account.account_id)
            .await?
        {
            return Err(anyhow!(Error::SecretRepository(
                "Deleting secret in repository returned false.".to_string()
            )));
        };

        if account_repository
            .delete_account(&self.account.user_id)
            .await?
            .is_none()
        {
            return Err(anyhow!(Error::AccountRepository(
                "Account repository returned None on insertion.".to_string()
            )));
        };
        Ok(())
    }
}
