use crate::application::errors::AccountOperation;
use crate::domain::entities::Account;
use crate::domain::traits::AccessHierarchy;
use crate::errors::{ApplicationError, Error};
use crate::ports::repositories::{AccountRepository, SecretRepository};

use std::sync::Arc;

use crate::errors::Result;
use tracing::{debug, error, info, warn};

/// Removes the given account and its corresponding secret from repositories.
/// Implements a compensating action: if account deletion fails after removing
/// the secret, the secret is restored (best-effort) and an error is returned.
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
    /// Creates a deletion service for the given account.
    ///
    /// This constructor is side-effect free; it does not touch any repositories.
    /// Invoke [`from_repositories`](Self::from_repositories) to perform the actual deletion with
    /// compensating secret restoration if the account removal fails.
    pub fn delete(account: Account<R, G>) -> Self {
        Self { account }
    }

    /// Performs the deletion workflow against the provided repositories.
    ///
    /// Workflow:
    /// 1. Removes (and returns) the secret associated with the account, caching it locally.
    /// 2. Attempts to delete the account.
    /// 3. If the account deletion fails, a compensating action re-inserts the cached secret
    ///    (best-effort) and an error is returned describing the restoration result.
    ///
    /// Returns:
    /// - Ok(()) if both secret and account are deleted successfully.
    /// - Err(_) if either removing the secret failed (None returned) or account deletion
    ///   failed (with secret restoration attempted).
    pub async fn from_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> Result<()>
    where
        AccRepo: AccountRepository<R, G>,
        SecRepo: SecretRepository,
    {
        let user_id = &self.account.user_id;
        let account_id = &self.account.account_id;

        // Remove and cache the secret so it can be restored if account deletion fails.
        info!(%user_id, %account_id, "Starting account deletion");
        let Some(secret) = secret_repository.delete_secret(account_id).await? else {
            error!(%user_id, %account_id, "Secret missing for account deletion attempt");
            return Err(Error::Application(ApplicationError::AccountService {
                operation: AccountOperation::Delete,
                message: "Secret not found".to_string(),
                account_id: Some(account_id.to_string()),
            }));
        };
        debug!(%user_id, %account_id, "Secret removed for account");

        // Delete the account second. If this fails, attempt to restore the secret.
        if account_repository.delete_account(user_id).await?.is_none() {
            error!(%user_id, %account_id, "Account deletion failed; attempting secret restore");
            let restore_result = secret_repository.store_secret(secret).await;
            match restore_result {
                Ok(true) => {
                    warn!(%user_id, %account_id, "Secret restored after account deletion failure");
                }
                Ok(false) => {
                    error!(%user_id, %account_id, "Secret restore reported false after account deletion failure");
                }
                Err(ref e) => {
                    error!(error = %e, %user_id, %account_id, "Secret restore failed after account deletion failure");
                }
            }

            return Err(Error::Application(ApplicationError::AccountService {
                operation: AccountOperation::Delete,
                message: "Account deletion failed".to_string(),
                account_id: Some(account_id.to_string()),
            }));
        }

        info!(%user_id, %account_id, "Account deletion succeeded");
        Ok(())
    }
}
