use crate::{accounts::Account, utils::AccessHierarchy};

use anyhow::Result;

/// An account storage service has access to the collection of passports
/// known to your application.
pub trait AccountStorageService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Stores the given account in the storage returning it again on success.
    fn store(&self, account: Account<R, G>) -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Deletes the account from the storage.
    fn delete(&self, username: &str) -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Updates the given account in the storage returning it again on success.
    fn update(&self, account: Account<R, G>)
    -> impl Future<Output = Result<Option<Account<R, G>>>>;

    /// Returns the account for the given `username`.
    fn query_by_username(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<Account<R, G>>>>;
}
