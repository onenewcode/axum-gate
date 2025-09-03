use axum_gate::{
    Account, AccountDeleteService, AccountInsertService, AccountRepository, AccessHierarchy,
    CredentialsVerifier, Group, Role, SecretRepository,
};
use axum_gate::domain::values::VerificationResult;
use axum_gate::errors::{AccountOperation, ApplicationError, Error};
use axum_gate::infrastructure::repositories::memory::{MemoryAccountRepository, MemorySecretRepository};

use std::sync::Arc;

/// A repository wrapper that simulates a failing delete operation while keeping all
/// other operations functional. This allows us to test the compensating behavior
/// of `AccountDeleteService` (i.e., restoring the secret).
#[derive(Clone)]
struct FailingDeleteAccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    inner: MemoryAccountRepository<R, G>,
}

impl<R, G> FailingDeleteAccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn new(inner: MemoryAccountRepository<R, G>) -> Self {
        Self { inner }
    }
}

impl<R, G> AccountRepository<R, G> for FailingDeleteAccountRepository<R, G>
where
    Account<R, G>: Clone,
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    // Pass-through to inner repository
    fn store_account(
        &self,
        account: Account<R, G>,
    ) -> impl std::future::Future<Output = axum_gate::errors::Result<Option<Account<R, G>>>> {
        self.inner.store_account(account)
    }

    fn update_account(
        &self,
        account: Account<R, G>,
    ) -> impl std::future::Future<Output = axum_gate::errors::Result<Option<Account<R, G>>>> {
        self.inner.update_account(account)
    }

    fn query_account_by_user_id(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = axum_gate::errors::Result<Option<Account<R, G>>>> {
        self.inner.query_account_by_user_id(user_id)
    }

    // Intentionally fail by returning Ok(None) always (simulating a failed deletion)
    fn delete_account(
        &self,
        _user_id: &str,
    ) -> impl std::future::Future<Output = axum_gate::errors::Result<Option<Account<R, G>>>> {
        async { Ok(None) }
    }
}

/// Ensures the happy-path: account and secret are both removed, and the operation succeeds.
#[tokio::test]
async fn account_and_secret_are_deleted_successfully() {
    let account_repository = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repository = Arc::new(MemorySecretRepository::default());

    // Create account + secret
    let account = AccountInsertService::insert("user.success@example.com", "password")
        .with_roles(vec![Role::User])
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await
        .expect("Insertion should succeed")
        .expect("Account should be returned");

    // Sanity: account exists
    assert!(
        account_repository
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap()
            .is_some()
    );

    // Perform deletion
    AccountDeleteService::delete(account.clone())
        .from_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await
        .expect("Deletion should succeed");

    // Account gone
    assert!(
        account_repository
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap()
            .is_none()
    );

    // Secret gone (verifying credentials should return Unauthorized since secret removed)
    let verify_result = secret_repository
        .verify_credentials(axum_gate::Credentials::new(
            &account.account_id,
            "password",
        ))
        .await
        .unwrap();
    assert_eq!(
        verify_result,
        VerificationResult::Unauthorized,
        "Secret should be deleted"
    );
}

/// Simulates a failure in account deletion causing compensating secret restoration.
/// Expectations:
/// - Service returns an error with AccountOperation::Delete
/// - Secret is restored (so credentials verification succeeds)
/// - Account still exists (since deletion failed)
#[tokio::test]
async fn secret_is_restored_when_account_deletion_fails() {
    let inner_repo = MemoryAccountRepository::<Role, Group>::default();
    let failing_repo = Arc::new(FailingDeleteAccountRepository::new(inner_repo));
    let secret_repository = Arc::new(MemorySecretRepository::default());

    // Create account + secret through insert service using failing repo for account storage
    let account = AccountInsertService::insert("user.compensate@example.com", "secret_pw")
        .with_roles(vec![Role::User])
        .into_repositories(Arc::clone(&failing_repo), Arc::clone(&secret_repository))
        .await
        .expect("Insertion should succeed")
        .expect("Account should be returned");

    // Sanity: account + secret usable
    let verify_ok = secret_repository
        .verify_credentials(axum_gate::Credentials::new(
            &account.account_id,
            "secret_pw",
        ))
        .await
        .unwrap();
    assert_eq!(verify_ok, VerificationResult::Ok);

    // Perform deletion; expect error
    let deletion_result = AccountDeleteService::delete(account.clone())
        .from_repositories(Arc::clone(&failing_repo), Arc::clone(&secret_repository))
        .await;

    // Must be an application error for deletion
    match deletion_result {
        Err(Error::Application(ApplicationError::AccountService {
            operation: AccountOperation::Delete,
            message,
            account_id,
        })) => {
            assert_eq!(account_id, Some(account.account_id.to_string()));
            assert_eq!(message, "Account deletion failed");
        }
        other => panic!("Expected AccountService delete error, got: {other:?}"),
    }

    // Account should still exist because failing repo never deletes
    assert!(
        failing_repo
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap()
            .is_some(),
        "Account should remain since deletion failed"
    );

    // Secret should have been restored (credentials still verify)
    let verify_again = secret_repository
        .verify_credentials(axum_gate::Credentials::new(
            &account.account_id,
            "secret_pw",
        ))
        .await
        .unwrap();
    assert_eq!(
        verify_again,
        VerificationResult::Ok,
        "Secret should have been restored"
    );
}

/// Ensures that if the secret is missing beforehand, the service errors early and
/// leaves the account untouched.
#[tokio::test]
async fn deletion_fails_if_secret_missing_and_account_remains() {
    let account_repository = Arc::new(MemoryAccountRepository::<Role, Group>::default());
    let secret_repository = Arc::new(MemorySecretRepository::default());

    // Manually insert account WITHOUT inserting a secret.
    let account = Account::new("user.nosecret@example.com", &[Role::User], &[Group::new("g")]);
    let account = account_repository
        .store_account(account)
        .await
        .unwrap()
        .expect("Account stored");

    // Attempt deletion (should fail because secret_repository.delete_secret returns None)
    let result = AccountDeleteService::delete(account.clone())
        .from_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await;

    match result {
        Err(Error::Application(ApplicationError::AccountService {
            operation: AccountOperation::Delete,
            message,
            account_id,
        })) => {
            assert_eq!(message, "Secret not found");
            assert_eq!(account_id, Some(account.account_id.to_string()));
        }
        other => panic!("Expected secret not found application error, got: {other:?}"),
    }

    // Account should still exist
    assert!(
        account_repository
            .query_account_by_user_id(&account.user_id)
            .await
            .unwrap()
            .is_some(),
        "Account should remain since deletion aborted early"
    );
}
