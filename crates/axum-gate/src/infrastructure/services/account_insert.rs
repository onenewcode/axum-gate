use crate::{
    Account, Error,
    domain::traits::AccessHierarchy,
    domain::values::secrets::Secret,
    infrastructure::hashing::Argon2Hasher,
    infrastructure::services::{AccountRepositoryService, SecretRepositoryService},
};

use std::sync::Arc;

use anyhow::{Result, anyhow};
use roaring::RoaringBitmap;
use tracing::debug;

/// Ergonomic service that is able to insert/register a new [Account] to the repositories.
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

    /// Adds the given permission bitmap to the [Account].
    ///
    /// Use this with the zero-synchronization permission system:
    /// ```rust
    /// use axum_gate::{PermissionChecker, AccountInsertService, Role, Group};
    /// use roaring::RoaringBitmap;
    ///
    /// let mut permissions = RoaringBitmap::new();
    /// PermissionChecker::grant_permission(&mut permissions, "read:file");
    /// PermissionChecker::grant_permission(&mut permissions, "write:file");
    ///
    /// let service = AccountInsertService::<Role, Group>::insert("user@example.com", "password")
    ///     .with_permissions(permissions);
    /// ```
    pub fn with_permissions(self, permissions: RoaringBitmap) -> Self {
        Self {
            permissions,
            ..self
        }
    }

    /// Adds the created [Account] to the repositories.
    pub async fn into_repositories<AccRepo, SecRepo>(
        self,
        account_repository: Arc<AccRepo>,
        secret_repository: Arc<SecRepo>,
    ) -> Result<Option<Account<R, G>>>
    where
        AccRepo: AccountRepositoryService<R, G>,
        SecRepo: SecretRepositoryService,
    {
        let account = Account::new(&self.user_id, &self.roles, &self.groups)
            .with_permissions(self.permissions);
        debug!("Created account.");
        let Some(account) = account_repository.store_account(account).await? else {
            return Err(anyhow!(Error::AccountRepository(
                "Account repository returned None on insertion.".to_string()
            )));
        };
        debug!("Stored account in account repository.");
        let id = &account.account_id;
        let secret = Secret::new(id, &self.secret, Argon2Hasher)?;
        if !secret_repository.store_secret(secret).await? {
            Err(anyhow!(Error::SecretRepository(
                "Storing secret in repository returned false.".to_string()
            )))
        } else {
            debug!("Stored secret in secret repository.");
            Ok(Some(account))
        }
    }
}
