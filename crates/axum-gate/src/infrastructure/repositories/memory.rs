//! In-memory storage implementations for development and testing.
//!
//! This module provides repository implementations that store all data in memory.
//! These are ideal for development, testing, and small applications that don't
//! require persistent storage.
//!
//! # Features
//! - Zero configuration required
//! - Fast operations (no I/O)
//! - Perfect for unit tests and development
//! - Thread-safe with async support
//! - Automatic cleanup when dropped
//!
//! # Quick Start
//!
//! ```rust
//! use axum_gate::{Account, Role, Group, Secret, Argon2Hasher};
//! use axum_gate::{AccountRepository, SecretRepository};
//! use axum_gate::memory::{MemoryAccountRepository, MemorySecretRepository};
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! // Create repositories
//! let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
//! let secret_repo = Arc::new(MemorySecretRepository::default());
//!
//! // Create an account
//! let account = Account::new("user@example.com", &[Role::User], &[Group::new("staff")]);
//! let stored_account = account_repo.store_account(account).await.unwrap().unwrap();
//!
//! // Create corresponding secret
//! let secret = Secret::new(&stored_account.account_id, "password", Argon2Hasher).unwrap();
//! secret_repo.store_secret(secret).await.unwrap();
//!
//! // Query the account
//! let found = account_repo.query_account_by_user_id("user@example.com").await.unwrap();
//! assert!(found.is_some());
//! # });
//! ```
//!
//! # Creating from Existing Data
//!
//! ```rust
//! use axum_gate::{Account, Role, Group, Secret};
//! use axum_gate::memory::{MemoryAccountRepository, MemorySecretRepository};
//!
//! // Create repositories with pre-populated data
//! let accounts = vec![
//!     Account::new("admin@example.com", &[Role::Admin], &[]),
//!     Account::new("user@example.com", &[Role::User], &[Group::new("staff")]),
//! ];
//! let account_repo = MemoryAccountRepository::from(accounts);
//!
//! let secrets = vec![/* your secrets */];
//! let secret_repo = MemorySecretRepository::from(secrets);
//! ```

use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::{Secret, VerificationResult};
use crate::errors::{Error, PortError, RepositoryType, Result};
use crate::infrastructure::hashing::Argon2Hasher;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::{AccountRepository, SecretRepository};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

/// In-memory repository for storing and retrieving user accounts.
///
/// This repository stores all account data in memory using a HashMap with the user ID
/// as the key. It's thread-safe and supports concurrent access through async read/write locks.
///
/// # Performance Characteristics
/// - O(1) lookup by user ID
/// - Thread-safe with RwLock
/// - No persistence (data lost when dropped)
/// - Suitable for up to thousands of accounts
///
/// # Example
/// ```rust
/// use axum_gate::{Account, Role, Group, AccountRepository};
/// use axum_gate::memory::MemoryAccountRepository;
/// use std::sync::Arc;
///
/// # tokio_test::block_on(async {
/// let repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
///
/// // Store an account
/// let account = Account::new("user@example.com", &[Role::User], &[]);
/// let stored = repo.store_account(account).await.unwrap();
///
/// // Query the account
/// let found = repo.query_account_by_user_id("user@example.com").await.unwrap();
/// assert!(found.is_some());
/// # });
/// ```
#[derive(Clone)]
pub struct MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    accounts: Arc<RwLock<HashMap<String, Account<R, G>>>>,
}

impl<R, G> Default for MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn default() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<R, G> From<Vec<Account<R, G>>> for MemoryAccountRepository<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn from(value: Vec<Account<R, G>>) -> Self {
        let mut accounts = HashMap::new();
        for val in value {
            let id = val.user_id.clone();
            accounts.insert(id, val);
        }
        let accounts = Arc::new(RwLock::new(accounts));
        Self { accounts }
    }
}

impl<R, G> AccountRepository<R, G> for MemoryAccountRepository<R, G>
where
    Account<R, G>: Clone,
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    async fn query_account_by_user_id(&self, user_id: &str) -> Result<Option<Account<R, G>>> {
        let read = self.accounts.read().await;
        Ok(read.get(user_id).cloned())
    }
    async fn store_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        let id = account.user_id.clone();
        let mut write = self.accounts.write().await;
        write.insert(id, account.clone());
        Ok(Some(account))
    }
    async fn delete_account(&self, account_id: &str) -> Result<Option<Account<R, G>>> {
        let mut write = self.accounts.write().await;
        if !write.contains_key(account_id) {
            return Ok(None);
        }
        Ok(write.remove(account_id))
    }
    async fn update_account(&self, account: Account<R, G>) -> Result<Option<Account<R, G>>> {
        self.store_account(account).await
    }
}
/// In-memory repository for storing and managing user authentication secrets.
///
/// This repository stores password hashes and other authentication secrets in memory.
/// It's designed to work alongside `MemoryAccountRepository` and implements both
/// `SecretRepository` and `CredentialsVerifier` traits for complete authentication support.
///
/// # Security Note
/// While this stores password hashes (not plain passwords), the data is kept in memory
/// and will be lost when the application stops. For production use, consider persistent
/// storage implementations.
///
/// # Example Usage
/// ```rust
/// use axum_gate::{Secret, Credentials, VerificationResult, Argon2Hasher};
/// use axum_gate::{SecretRepository, CredentialsVerifier};
/// use axum_gate::memory::MemorySecretRepository;
/// use uuid::Uuid;
///
/// # tokio_test::block_on(async {
/// let repo = MemorySecretRepository::default();
/// let account_id = Uuid::now_v7();
///
/// // Store a secret (password hash)
/// let secret = Secret::new(&account_id, "user_password", Argon2Hasher).unwrap();
/// repo.store_secret(secret).await.unwrap();
///
/// // Verify credentials
/// let credentials = Credentials::new(&account_id, "user_password");
/// let result = repo.verify_credentials(credentials).await.unwrap();
/// assert_eq!(result, VerificationResult::Ok);
///
/// // Test wrong password
/// let wrong_creds = Credentials::new(&account_id, "wrong_password");
/// let result = repo.verify_credentials(wrong_creds).await.unwrap();
/// assert_eq!(result, VerificationResult::Unauthorized);
/// # });
/// ```
///
/// # Creating from Existing Data
/// ```rust
/// use axum_gate::{Secret, Argon2Hasher};
/// use axum_gate::memory::MemorySecretRepository;
/// use uuid::Uuid;
///
/// let secrets = vec![
///     Secret::new(&Uuid::now_v7(), "admin_pass", Argon2Hasher).unwrap(),
///     Secret::new(&Uuid::now_v7(), "user_pass", Argon2Hasher).unwrap(),
/// ];
/// let repo = MemorySecretRepository::from(secrets);
/// ```
#[derive(Clone)]
pub struct MemorySecretRepository {
    store: Arc<RwLock<HashMap<Uuid, Secret>>>,
}

impl Default for MemorySecretRepository {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl From<Vec<Secret>> for MemorySecretRepository {
    fn from(value: Vec<Secret>) -> Self {
        let mut store = HashMap::with_capacity(value.len());
        value.into_iter().for_each(|v| {
            store.insert(v.account_id, v);
        });
        let store = Arc::new(RwLock::new(store));
        Self { store }
    }
}

impl SecretRepository for MemorySecretRepository {
    async fn store_secret(&self, secret: Secret) -> Result<bool> {
        let already_present = {
            let read = self.store.read().await;
            read.contains_key(&secret.account_id)
        };

        if already_present {
            return Err(Error::Port(PortError::Repository {
                repository: RepositoryType::Secret,
                message: "AccountID is already present".to_string(),
                operation: None,
            }));
        }

        let mut write = self.store.write().await;
        debug!("Got write lock on secret repository.");

        if write.insert(secret.account_id, secret).is_some() {
            return Err(Error::Port(PortError::Repository {
                repository: RepositoryType::Secret,
                message: "This should never occur because it is checked if the key is already present a few lines earlier".to_string(),
                operation: Some("store".to_string()),
            }));
        };
        Ok(true)
    }

    async fn delete_secret(&self, id: &Uuid) -> Result<bool> {
        let mut write = self.store.write().await;
        Ok(write.remove(id).is_some())
    }

    async fn update_secret(&self, secret: Secret) -> Result<()> {
        let mut write = self.store.write().await;
        write.insert(secret.account_id, secret);
        Ok(())
    }
}

impl CredentialsVerifier<Uuid> for MemorySecretRepository {
    async fn verify_credentials(
        &self,
        credentials: Credentials<Uuid>,
    ) -> Result<VerificationResult> {
        use crate::ports::auth::HashingService;
        use subtle::Choice;

        let read = self.store.read().await;

        // Get stored secret or use dummy hash to ensure constant-time operation
        let (stored_secret_str, user_exists_choice) = match read.get(&credentials.id) {
            Some(stored_secret) => (stored_secret.secret.as_str(), Choice::from(1u8)),
            None => {
                // Use a realistic dummy Argon2 hash to maintain constant timing
                // This hash was generated with the same parameters as real hashes
                let dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3ODkwYWJjZGVmZ2hpams$+U4VpzOTOuH3Lz3dN2CX2z6VZhUZP1c1xN1y2Z3Z4aA";
                (dummy_hash, Choice::from(0u8))
            }
        };

        // ALWAYS perform Argon2 verification (constant time regardless of user existence)
        let hasher = Argon2Hasher;
        let hash_verification_result =
            hasher.verify_value(&credentials.secret, stored_secret_str)?;

        // Convert hash verification result to Choice for constant-time operations
        let hash_matches_choice = Choice::from(match hash_verification_result {
            VerificationResult::Ok => 1u8,
            VerificationResult::Unauthorized => 0u8,
        });

        // Combine results using constant-time AND operation
        // Success only if: user exists AND password hash matches
        let final_success_choice = user_exists_choice & hash_matches_choice;

        // Convert back to VerificationResult
        let final_result = if bool::from(final_success_choice) {
            VerificationResult::Ok
        } else {
            VerificationResult::Unauthorized
        };

        Ok(final_result)
    }
}
