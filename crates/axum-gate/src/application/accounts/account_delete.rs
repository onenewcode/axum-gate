use crate::domain::entities::Account;
use crate::domain::traits::AccessHierarchy;
use crate::errors::{AccountOperation, ApplicationError, Error};
use crate::ports::repositories::{AccountRepository, SecretRepository};

use std::sync::Arc;

use crate::errors::Result;

/// Removes the given account and its corresponding secret from repositories.
pub struct AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    account: Account<R, G>,
}

impl<R, G> AccountDeleteService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
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
        SecRepo: SecretRepository,
    {
        if !secret_repository
            .delete_secret(&self.account.account_id)
            .await?
        {
            return Err(Error::Application(ApplicationError::AccountService {
                operation: AccountOperation::Delete,
                message: "Deleting secret in repository returned false".to_string(),
                account_id: Some(self.account.account_id.to_string()),
            })
            .into());
        };

        if account_repository
            .delete_account(&self.account.user_id)
            .await?
            .is_none()
        {
            return Err(Error::Application(ApplicationError::AccountService {
                operation: AccountOperation::Delete,
                message: "Account repository returned None on deletion".to_string(),
                account_id: Some(self.account.account_id.to_string()),
            })
            .into());
        };
        Ok(())
    }
}
