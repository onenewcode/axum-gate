use crate::{domain::entities::Account, domain::traits::AccessHierarchy};

use crate::errors::Result;
use std::future::Future;

/// An account repository has access to the collection of [Account]s
/// known to your application.
pub trait AccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Stores the given account in the repository returning it again on success.
    fn store_account(
        &self,
        account: Account<R, G>,
    ) -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Deletes the account from the repository.
    fn delete_account(&self, user_id: &str) -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Updates the given account in the repository returning it again on success.
    fn update_account(
        &self,
        account: Account<R, G>,
    ) -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Returns the account for the given `user_id`.
    fn query_account_by_user_id(
        &self,
        user_id: &str,
    ) -> impl Future<Output = Result<Option<Account<R, G>>>>;
}
