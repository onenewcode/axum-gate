use crate::domain::entities::Credentials;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::VerificationResult;
use crate::infrastructure::jwt::{JwtClaims, RegisteredClaims};
use crate::ports::Codec;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::AccountRepository;
use crate::prelude::Account;

use std::sync::Arc;
use subtle::Choice;
use tracing::{debug, error};
use uuid::Uuid;

/// Result of a login attempt
#[derive(Debug)]
pub enum LoginResult {
    /// Login successful with JWT token
    Success(String),
    /// Invalid credentials (covers both non-existent users and wrong passwords)
    InvalidCredentials,
    /// Internal error occurred
    InternalError(String),
}

/// Application service for handling user login
pub struct LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<R, G> LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Create a new login service
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Authenticate a user and generate a JWT token
    pub async fn authenticate<CredVeri, AccRepo, C>(
        &self,
        credentials: Credentials<String>,
        registered_claims: RegisteredClaims,
        credentials_verifier: Arc<CredVeri>,
        account_repository: Arc<AccRepo>,
        codec: Arc<C>,
    ) -> LoginResult
    where
        CredVeri: CredentialsVerifier<Uuid>,
        AccRepo: AccountRepository<R, G>,
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
    {
        // Step 1: Always query account (timing consistent for database lookup)
        let account_query_result = account_repository
            .query_account_by_user_id(&credentials.id)
            .await;

        // Step 2: Extract account info with constant-time branching protection
        let (account_opt, verification_uuid, user_exists_choice, query_error_opt) =
            match account_query_result {
                Ok(Some(acc)) => {
                    debug!("Account found for user_id: {}", credentials.id);
                    (Some(acc.clone()), acc.account_id, Choice::from(1u8), None)
                }
                Ok(None) => {
                    debug!("Account not found for user_id: {}", credentials.id);
                    // Use consistent dummy UUID to ensure we always perform credential verification
                    // This UUID is fixed to ensure consistent timing behavior and won't collide with real UUIDs
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), None)
                }
                Err(e) => {
                    error!("Error querying account: {}", e);
                    // Use consistent dummy UUID for error cases too
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), Some(e))
                }
            };

        // Step 3: Return early only for database errors, not missing users
        if let Some(error) = query_error_opt {
            return LoginResult::InternalError(error.to_string());
        }

        // Step 4: ALWAYS verify credentials (constant time - no early returns)
        let creds_to_verify = Credentials::new(&verification_uuid, &credentials.secret);
        let verification_result = credentials_verifier
            .verify_credentials(creds_to_verify)
            .await;

        // Step 5: Determine authentication success using constant-time operations
        let auth_success_choice = match verification_result {
            Ok(VerificationResult::Ok) => {
                debug!(
                    "Credentials verified successfully for UUID: {}",
                    verification_uuid
                );
                Choice::from(1u8)
            }
            Ok(VerificationResult::Unauthorized) => {
                debug!(
                    "Credentials verification failed for UUID: {}",
                    verification_uuid
                );
                Choice::from(0u8)
            }
            Err(e) => {
                error!("Error verifying credentials: {}", e);
                return LoginResult::InternalError(e.to_string());
            }
        };

        // Step 6: Combine conditions using constant-time AND operation
        // Authentication succeeds only if: user exists AND credentials are valid
        let final_success_choice = user_exists_choice & auth_success_choice;
        let login_successful: bool = final_success_choice.into();

        // Step 7: Handle result based on final success state
        if login_successful {
            if let Some(account) = account_opt {
                // Generate JWT token for successful authentication
                let claims = JwtClaims::new(account, registered_claims);
                let jwt = match codec.encode(&claims) {
                    Ok(token) => token,
                    Err(e) => {
                        error!("Error encoding JWT: {}", e);
                        return LoginResult::InternalError(e.to_string());
                    }
                };

                let jwt_string = match String::from_utf8(jwt) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Error converting JWT to string: {}", e);
                        return LoginResult::InternalError(e.to_string());
                    }
                };

                debug!("Login successful, JWT generated");
                LoginResult::Success(jwt_string)
            } else {
                // This should never happen due to our constant-time logic, but handle gracefully
                error!("Internal error: login marked successful but no account available");
                LoginResult::InternalError("Authentication state inconsistency".to_string())
            }
        } else {
            // Always return InvalidCredentials for any authentication failure
            // This prevents distinguishing between "user not found" and "wrong password"
            debug!("Login failed - invalid credentials");
            LoginResult::InvalidCredentials
        }
    }
}

impl<R, G> Default for LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::Secret;
    use crate::infrastructure::hashing::Argon2Hasher;
    use crate::infrastructure::jwt::{JsonWebToken, JwtClaims};
    use crate::infrastructure::repositories::memory::{
        MemoryAccountRepository, MemorySecretRepository,
    };
    use crate::prelude::{Group, Role};
    use std::time::Instant;

    #[tokio::test]
    async fn test_timing_attack_protection() {
        // Setup repositories and services
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::default());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        // Create a test account
        let existing_user = "existing@example.com";
        let password = "test_password";
        let account = Account::new(existing_user, &[Role::User], &[Group::new("test")]);
        let stored_account = account_repo.store_account(account).await.unwrap().unwrap();

        // Store corresponding secret
        let secret = Secret::new(&stored_account.account_id, password, Argon2Hasher).unwrap();
        use crate::ports::repositories::SecretRepository;
        secret_repo.store_secret(secret).await.unwrap();

        let registered_claims = crate::infrastructure::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        // Test timing for non-existent user
        let nonexistent_credentials =
            Credentials::new(&"nonexistent@example.com".to_string(), "any_password");
        let start = Instant::now();
        let result1 = login_service
            .authenticate(
                nonexistent_credentials,
                registered_claims.clone(),
                secret_repo.clone(),
                account_repo.clone(),
                jwt_codec.clone(),
            )
            .await;
        let time_nonexistent = start.elapsed();

        // Test timing for existing user with wrong password
        let wrong_credentials = Credentials::new(&existing_user.to_string(), "wrong_password");
        let start = Instant::now();
        let result2 = login_service
            .authenticate(
                wrong_credentials,
                registered_claims.clone(),
                secret_repo.clone(),
                account_repo.clone(),
                jwt_codec.clone(),
            )
            .await;
        let time_wrong_password = start.elapsed();

        // Test timing for existing user with correct password
        let correct_credentials = Credentials::new(&existing_user.to_string(), password);
        let start = Instant::now();
        let result3 = login_service
            .authenticate(
                correct_credentials,
                registered_claims,
                secret_repo,
                account_repo,
                jwt_codec,
            )
            .await;
        let time_correct = start.elapsed();

        // Verify results are as expected
        assert!(matches!(result1, LoginResult::InvalidCredentials));
        assert!(matches!(result2, LoginResult::InvalidCredentials));
        assert!(matches!(result3, LoginResult::Success(_)));

        // Verify timing attack protection:
        // The time difference between nonexistent user and wrong password should be minimal
        // Both should involve Argon2 verification, so timing should be similar
        let timing_diff = if time_nonexistent > time_wrong_password {
            time_nonexistent - time_wrong_password
        } else {
            time_wrong_password - time_nonexistent
        };

        // The timing difference should be less than 15ms (generous threshold for test stability)
        // In practice, it should be much smaller (microseconds) due to constant-time operations
        println!(
            "Timing - Nonexistent: {:?}, Wrong password: {:?}, Correct: {:?}, Diff: {:?}",
            time_nonexistent, time_wrong_password, time_correct, timing_diff
        );

        // This test verifies that both nonexistent and wrong password cases take similar time
        // The threshold accounts for system variations while ensuring timing attack protection
        // The improvement should be dramatic compared to the unprotected version
        assert!(
            timing_diff.as_millis() < 15,
            "Timing difference too large: {:?}ms. This suggests a timing attack vulnerability.",
            timing_diff.as_millis()
        );

        // Verify that both failed cases take at least some minimum time (Argon2 is slow)
        assert!(
            time_nonexistent.as_millis() > 5,
            "Nonexistent user check too fast - may not be doing Argon2"
        );
        assert!(
            time_wrong_password.as_millis() > 5,
            "Wrong password check too fast - may not be doing Argon2"
        );
    }

    #[tokio::test]
    async fn test_login_result_no_user_enumeration() {
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::default());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        let registered_claims = crate::infrastructure::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        // Test that nonexistent user returns InvalidCredentials (not AccountNotFound)
        let nonexistent_credentials =
            Credentials::new(&"nonexistent@example.com".to_string(), "password");
        let result = login_service
            .authenticate(
                nonexistent_credentials,
                registered_claims,
                secret_repo,
                account_repo,
                jwt_codec,
            )
            .await;

        // This should be InvalidCredentials, never AccountNotFound
        // This prevents username enumeration through different error messages
        assert!(matches!(result, LoginResult::InvalidCredentials));
    }
}
